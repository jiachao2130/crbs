// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `config.schema.json` 与各侧 config 结构体的完备性测试。手写 schema（案 B：
//! 不引 schemars）无法自动感知新增字段，以五道防线钉死漂移面（细节见各测试 doc）：
//! 1. `default_config_fields_exist_in_schema`：默认配置序列化的叶子路径 ⊆ schema def properties。
//! 2. `schema_properties_deserialize_back_into_structs`：schema 对象 def 属性反推 TOML 喂真实结构体。
//! 3. `config_module_struct_inventory`：config 面 Deserialize 类型登记清单与 schema `$defs` 双向相等。
//! 4. `schema_default_prose_matches_serde_defaults`：schema "Default: X" prose 与 serde default fn 返回值逐项一致。
//! 5. `example_config_keys_declared_in_schema`：examples/config 样例键 ⊆ 对应 def properties。
//!
//! 防线边界：skip_serializing 字段防线 1 探测不到（RemoteProfile.token），由 2 兜底；
//! crbs-worker 跨 crate 不可见：防线 2 对 WorkerConfig def 不适用、防线 4 不核其
//! 默认值文案——由防线 5 样例键 + crbs-worker 自身测试兜底。
//! 扫描范围 = crbs-core config + privilege + crbs-worker config.rs。

use std::collections::BTreeMap;

use serde_json::Value;

/// 解析嵌入的 schema（非法 JSON 在此兜底）。
fn schema() -> Value {
    serde_json::from_str(crate::config::CONFIG_SCHEMA_JSON).expect("embedded config schema parses")
}

fn resolve_ref<'a>(prop: &'a Value, schema: &'a Value) -> &'a Value {
    match prop.get("$ref").and_then(Value::as_str) {
        Some(reference) => {
            let name = reference
                .strip_prefix("#/$defs/")
                .unwrap_or_else(|| panic!("unsupported $ref {reference}"));
            &schema["$defs"][name]
        }
        None => prop,
    }
}

fn def_of<'a>(schema: &'a Value, name: &str) -> &'a Value {
    &schema["$defs"][name]
}

/// 收集叶子路径（对象/数组按 schema def 递归），返回 schema properties 解析不到的路径。
fn check_paths(
    value: &Value,
    def: &Value,
    prefix: &str,
    schema: &Value,
    missing: &mut Vec<String>,
) {
    let Value::Object(map) = value else {
        return; // 标量叶子：键存在性已由上层检查
    };
    let properties = def
        .get("properties")
        .unwrap_or_else(|| panic!("def at {prefix} has no properties"))
        .as_object()
        .expect("properties is an object");
    for (key, child) in map {
        let Some(prop) = properties.get(key) else {
            missing.push(format!(
                "{prefix}{key} (serialized value absent from schema properties)"
            ));
            continue;
        };
        let resolved = resolve_ref(prop, schema);
        match child {
            Value::Object(_) => {
                // 仅 def 有 properties 才递归；additionalProperties map（rpm_macros、hooks.pre）子键动态，视作叶子。
                if resolved.get("properties").is_some() {
                    check_paths(child, resolved, &format!("{prefix}{key}."), schema, missing);
                }
            }
            Value::Array(items) => {
                let item_def = resolved.get("items").map(|i| resolve_ref(i, schema));
                for element in items {
                    if let (Value::Object(_), Some(item_def)) = (element, item_def) {
                        check_paths(
                            element,
                            item_def,
                            &format!("{prefix}{key}."),
                            schema,
                            missing,
                        );
                    }
                }
            }
            _ => {} // 标量叶子
        }
    }
}

/// 防线 1：默认配置序列化后的每个字段路径必须在 schema 中存在。
#[test]
fn default_config_fields_exist_in_schema() {
    let schema = schema();

    // crbs.toml 侧：充实嵌套结构，保证每个子结构体至少出现一个实例。
    let crbs = crate::config::CrbsConfig {
        hooks: Some(crate::config::HooksConfig::default()),
        remote: crate::config::RemoteConfig {
            profiles: vec![crate::config::RemoteProfile {
                name: "hub".into(),
                url: "http://hub.example.com:9090".into(),
                token: None,
                token_env: None,
                token_file: None,
                ca_cert: None,
            }],
            ..Default::default()
        },
        ..crate::config::CrbsConfig::default()
    };

    let server = crate::config::ServerConfig {
        tls: Some(crate::config::ServerTlsConfig {
            cert: "/etc/crbs/tls/cert.pem".into(),
            key: "/etc/crbs/tls/key.pem".into(),
        }),
        ..crate::config::ServerConfig::default()
    };

    let mut missing = Vec::new();
    let crbs_json = serde_json::to_value(&crbs).expect("serialize CrbsConfig default");
    check_paths(
        &crbs_json,
        def_of(&schema, "CrbsConfig"),
        "CrbsConfig.",
        &schema,
        &mut missing,
    );
    let server_json = serde_json::to_value(&server).expect("serialize ServerConfig default");
    check_paths(
        &server_json,
        def_of(&schema, "ServerConfig"),
        "ServerConfig.",
        &schema,
        &mut missing,
    );

    assert!(
        missing.is_empty(),
        "schema drift: serialized config fields missing from config.schema.json \
         (add/fix the corresponding properties):\n  {}",
        missing.join("\n  ")
    );
}

/// schema 属性 → TOML 值行的三类形态。
enum PropShape {
    Scalar(String),
    Table,
    TableArray,
}

fn prop_shape(prop: &Value, schema: &Value) -> PropShape {
    let resolved = resolve_ref(prop, schema);
    if resolved.get("anyOf").is_some() {
        // BoolOrPackages：反推为 bool 形态即可证明键存在且可反序列化。
        return PropShape::Scalar("false".into());
    }
    match resolved.get("type").and_then(Value::as_str) {
        Some("string") => {
            let value = resolved
                .get("enum")
                .and_then(Value::as_array)
                .and_then(|vals| vals.first())
                .and_then(Value::as_str)
                .unwrap_or("x")
                .to_string();
            PropShape::Scalar(format!("\"{value}\""))
        }
        Some("integer") => PropShape::Scalar("1".into()),
        Some("number") => PropShape::Scalar("0.5".into()),
        Some("boolean") => PropShape::Scalar("true".into()),
        Some("array") => {
            // 元素为对象 def 的数组 → [[array-of-tables]]；其余反推为空数组。
            let items_is_object_def = resolved
                .get("items")
                .map(|i| resolve_ref(i, schema).get("properties").is_some())
                .unwrap_or(false);
            if items_is_object_def {
                PropShape::TableArray
            } else {
                PropShape::Scalar("[]".into())
            }
        }
        Some("object") => {
            if resolved.get("properties").is_some() {
                PropShape::Table
            } else {
                // additionalProperties map（如 rpm_macros / hooks.pre）→ 空 inline table。
                PropShape::Scalar("{}".into())
            }
        }
        other => panic!(
            "schema property with type {other:?} is not covered by the TOML generator — \
             extend schema_tests::prop_shape"
        ),
    }
}

/// 把对象类 def 反推成一份 TOML 文档（键序：标量 → 子表 → 子表数组）。
fn toml_document_for_def(def: &Value, schema: &Value) -> String {
    let mut out = String::new();
    emit_def(def, "", schema, &mut out);
    out
}

/// TOML 键输出：bare 键（字母/数字/下划线/连字符）直写；其余（如 `+base_packages`）加双引号，否则文档解析失败。
fn toml_key(key: &str) -> String {
    if !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        key.to_string()
    } else {
        format!("\"{key}\"")
    }
}

fn emit_def(def: &Value, path: &str, schema: &Value, out: &mut String) {
    let properties = def
        .get("properties")
        .expect("emit_def only handles object defs with properties")
        .as_object()
        .expect("properties is an object");
    // 节内键一律裸写（表头已带累积路径）；path 仅用于拼子表头。
    for (key, prop) in properties {
        if let PropShape::Scalar(value) = prop_shape(prop, schema) {
            out.push_str(&format!("{} = {value}\n", toml_key(key)));
        }
    }
    for (key, prop) in properties {
        if matches!(prop_shape(prop, schema), PropShape::Table) {
            out.push_str(&format!("\n[{}{}]\n", path, toml_key(key)));
            emit_def(
                resolve_ref(prop, schema),
                &format!("{path}{}.", toml_key(key)),
                schema,
                out,
            );
        }
    }
    for (key, prop) in properties {
        if matches!(prop_shape(prop, schema), PropShape::TableArray) {
            let item_def = resolve_ref(
                resolve_ref(prop, schema)
                    .get("items")
                    .expect("array property carries items"),
                schema,
            );
            out.push_str(&format!("\n[[{}{}]]\n", path, toml_key(key)));
            emit_def(item_def, &format!("{path}{}.", toml_key(key)), schema, out);
        }
    }
}

/// 防线 2：schema 对象 def 反推的 TOML 必须能被真实结构体（deny_unknown_fields）
/// 反序列化——schema 多写属性/错名/错型即红，required 字段存在性同获证明。
#[test]
fn schema_properties_deserialize_back_into_structs() {
    use crate::config::server::{LocalConfig, SubmitRateLimitConfig};
    use crate::config::{
        HooksConfig, LogSanitizationConfig, PublicAccessConfig, RemoteConfig, RemoteProfile,
        ServerConfig, ServerTlsConfig, SpecHooksConfig,
    };

    let schema = schema();
    type ParseFn = fn(&str) -> Result<(), String>;
    let cases: Vec<(&str, ParseFn)> = vec![
        ("CrbsConfig", |s| {
            toml::from_str::<crate::config::CrbsConfig>(s)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }),
        ("RemoteConfig", |s| {
            toml::from_str::<RemoteConfig>(s)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }),
        ("RemoteProfile", |s| {
            toml::from_str::<RemoteProfile>(s)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }),
        ("HooksConfig", |s| {
            toml::from_str::<HooksConfig>(s)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }),
        ("SpecHooksConfig", |s| {
            toml::from_str::<SpecHooksConfig>(s)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }),
        ("PostInitCommand", |s| {
            toml::from_str::<crate::config::PostInitCommand>(s)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }),
        ("ProductConfig", |s| {
            toml::from_str::<crate::config::ProductConfig>(s)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }),
        ("ResourceOverride", |s| {
            toml::from_str::<crate::config::ResourceOverride>(s)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }),
        ("RepoConfig", |s| {
            toml::from_str::<crate::config::RepoConfig>(s)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }),
        ("ServerConfig", |s| {
            toml::from_str::<ServerConfig>(s)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }),
        ("PublicAccessConfig", |s| {
            toml::from_str::<PublicAccessConfig>(s)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }),
        ("LogSanitizationConfig", |s| {
            toml::from_str::<LogSanitizationConfig>(s)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }),
        ("LocalConfig", |s| {
            toml::from_str::<LocalConfig>(s)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }),
        ("SubmitRateLimitConfig", |s| {
            toml::from_str::<SubmitRateLimitConfig>(s)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }),
        ("ServerTlsConfig", |s| {
            toml::from_str::<ServerTlsConfig>(s)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }),
    ];

    let mut failures = Vec::new();
    for (name, parse) in cases {
        let doc = toml_document_for_def(def_of(&schema, name), &schema);
        if let Err(error) = parse(&doc) {
            failures.push(format!(
                "{name}:\n--- generated toml ---\n{doc}--- error ---\n{error}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "schema drift: schema properties failed to deserialize into the real structs \
         (schema has unknown/misspelled/mistyped properties):\n{}",
        failures.join("\n")
    );
}

/// schema `$defs`（手写清单，双向核对）。
const SCHEMA_DEFS: &[&str] = &[
    "BoolOrPackages",
    "CrbsConfig",
    "HooksConfig",
    "LocalConfig",
    "LogSanitizationConfig",
    "PostInitCommand",
    "PrivilegedHelperMode",
    "ProductConfig",
    "PublicAccessConfig",
    "RemoteConfig",
    "RemoteProfile",
    "RepoConfig",
    "ResourceOverride",
    "SchedulerMode",
    "ServerConfig",
    "ServerTlsConfig",
    "SpecHooksConfig",
    "StartupMountGc",
    "SubmitRateLimitConfig",
    "WorkerConfig",
];

/// 非"配置文件形态"的类型：运行时合并结果 / wire 响应，永不入 schema（Config 无 Deserialize 不在扫描面）。
const NON_FILE_CONFIG: &[&str] = &["Hooks", "ProductDetail"];

/// 扫描 config 模块、privilege/mod.rs 与 crbs-worker config.rs 中全部 `Deserialize` 派生类型名。
fn scan_deserialize_types() -> BTreeMap<String, &'static str> {
    let mut found = BTreeMap::new();
    let mut scan_file = |rel: &'static str, text: &str| {
        let mut pending = false;
        for line in text.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("#[") {
                if trimmed.contains("Deserialize") {
                    pending = true;
                }
                continue;
            }
            let name = trimmed
                .strip_prefix("pub struct ")
                .or_else(|| trimmed.strip_prefix("pub enum "))
                .or_else(|| trimmed.strip_prefix("pub(crate) struct "))
                .or_else(|| trimmed.strip_prefix("pub(crate) enum "))
                .map(|rest| {
                    rest.chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect::<String>()
                });
            match name {
                Some(type_name) => {
                    if pending {
                        found.insert(type_name, rel);
                        pending = false;
                    }
                }
                None => {
                    if !trimmed.is_empty() {
                        // 中间插入普通代码行 → derive 上下文结束。
                        pending = false;
                    }
                }
            }
        }
    };

    let manifest = env!("CARGO_MANIFEST_DIR");
    for entry in std::fs::read_dir(format!("{manifest}/src/config")).expect("config dir") {
        let entry = entry.expect("config dir entry");
        if !entry.file_type().expect("file type").is_file() {
            continue;
        }
        let file_name = entry.file_name();
        let file_name = file_name.to_str().expect("utf8 file name");
        if !file_name.ends_with(".rs") {
            continue;
        }
        let rel: &'static str = Box::leak(format!("src/config/{file_name}").into_boxed_str());
        let text = std::fs::read_to_string(entry.path()).expect("read config source");
        scan_file(rel, &text);
    }
    scan_file(
        "src/privilege/mod.rs",
        &std::fs::read_to_string(format!("{manifest}/src/privilege/mod.rs"))
            .expect("read privilege source"),
    );
    // WorkerConfig def 在 schema 中手工维护；扫描其源文件把该 crate 的 Deserialize 类型纳入同一登记面。
    scan_file(
        "crbs-worker/src/config.rs",
        &std::fs::read_to_string(format!("{manifest}/../crbs-worker/src/config.rs"))
            .expect("read crbs-worker config source"),
    );
    found
}

/// 防线 3：config 面 Deserialize 类型必须登记处置，schema `$defs` 与登记清单双向相等。
#[test]
fn config_module_struct_inventory() {
    let scanned = scan_deserialize_types();

    let known: Vec<&str> = SCHEMA_DEFS.iter().chain(NON_FILE_CONFIG).copied().collect();
    let mut unknown: Vec<String> = scanned
        .keys()
        .filter(|name| !known.contains(&name.as_str()))
        .map(|name| {
            format!(
                "{name} ({}): new Deserialize type in the config surface — register it in \
                 schema_tests (SCHEMA_DEFS / NON_FILE_CONFIG / PRODUCT_SIDE_UNCOVERED) and, \
                 if file-facing, add a config.schema.json def",
                scanned[name]
            )
        })
        .collect();
    // 防线反向：登记进 SCHEMA_DEFS 的类型必须真实存在（防清单腐烂/改名残留）。
    for name in known {
        if !scanned.contains_key(name) {
            unknown.push(format!(
                "{name}: registered in schema_tests inventory but no such Deserialize type \
                 was found in the config surface (renamed/removed? update the inventory)"
            ));
        }
    }
    assert!(
        unknown.is_empty(),
        "config struct inventory drift:\n  {}",
        unknown.join("\n  ")
    );

    let schema = schema();
    let defs_in_schema: Vec<&str> = schema["$defs"]
        .as_object()
        .expect("$defs is an object")
        .keys()
        .map(String::as_str)
        .collect();
    let mut expected_defs = SCHEMA_DEFS.to_vec();
    expected_defs.sort_unstable();
    let mut actual_defs = defs_in_schema.clone();
    actual_defs.sort_unstable();
    assert_eq!(
        expected_defs, actual_defs,
        "config.schema.json $defs and the SCHEMA_DEFS inventory diverged"
    );
}

/// 冒烟：schema 自身形态合法——draft-07 声明在位、全部 $ref 可解析。
#[test]
fn schema_is_valid_with_resolvable_refs() {
    let schema = schema();
    assert_eq!(schema["$schema"], "http://json-schema.org/draft-07/schema#");
    let mut broken = Vec::new();
    fn walk(value: &Value, schema: &Value, broken: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                if let Some(reference) = map.get("$ref").and_then(Value::as_str) {
                    let target = reference.strip_prefix("#/$defs/");
                    match target {
                        Some(name) if schema["$defs"].get(name).is_some() => {}
                        _ => broken.push(reference.to_string()),
                    }
                }
                for child in map.values() {
                    walk(child, schema, broken);
                }
            }
            Value::Array(items) => {
                for item in items {
                    walk(item, schema, broken);
                }
            }
            _ => {}
        }
    }
    walk(&schema, &schema, &mut broken);
    assert!(
        broken.is_empty(),
        "unresolvable $refs in config.schema.json: {broken:?}"
    );
}

/// 防线 4：schema "Default: X" prose 与 serde 默认值逐项一致——期望值由调用
/// default fn 本身格式化，任一侧漂移即红；BoolOrPackages 走 serde_json（untagged，
/// `Bool(false)` → "false"）。覆盖 defaults.rs / server.rs / types.rs 全部 serde
/// default fn，唯一豁免 `default_ccache_dir`（派生占位，见下）；漏登由下方计数断言兜住。
#[test]
fn schema_default_prose_matches_serde_defaults() {
    use super::defaults as d;
    use super::server;
    use super::types as t;
    use crate::config::BoolOrPackages;

    fn bop(v: BoolOrPackages) -> String {
        serde_json::to_string(&v).expect("BoolOrPackages serializes")
    }

    let cases: Vec<(&str, &str, String)> = vec![
        // ── defaults.rs（CrbsConfig / ServerConfig 两侧的 serde 默认）──
        ("CrbsConfig", "builder_user", d::default_builder_user()),
        (
            "CrbsConfig",
            "builder_uid",
            d::default_builder_uid().to_string(),
        ),
        ("CrbsConfig", "builder_group", d::default_builder_group()),
        (
            "CrbsConfig",
            "builder_gid",
            d::default_builder_gid().to_string(),
        ),
        (
            "CrbsConfig",
            "crbs_root",
            d::default_engine_crbs_root().display().to_string(),
        ),
        (
            "ServerConfig",
            "crbs_root",
            d::default_crbs_root().display().to_string(),
        ),
        (
            "CrbsConfig",
            "shared_layer_gc_grace_hours",
            d::default_shared_layer_gc_grace_hours().to_string(),
        ),
        ("CrbsConfig", "shared_layer_staleness", "7d".to_string()),
        (
            "CrbsConfig",
            "result_gc_grace_hours",
            d::default_result_gc_grace_hours().to_string(),
        ),
        (
            "CrbsConfig",
            "build_max_retries",
            d::default_build_max_retries().to_string(),
        ),
        (
            "CrbsConfig",
            "build_retry_backoff_ms",
            d::default_build_retry_backoff_ms().to_string(),
        ),
        (
            "CrbsConfig",
            "resource_sample_interval_secs",
            d::default_resource_sample_interval_secs().to_string(),
        ),
        (
            "CrbsConfig",
            "package_url_cache_ttl_days",
            d::default_package_url_cache_ttl_days().to_string(),
        ),
        (
            "CrbsConfig",
            "base_snapshot_keep_generations",
            d::default_base_snapshot_keep_generations().to_string(),
        ),
        (
            "CrbsConfig",
            "reproduce_enabled",
            bop(d::default_reproduce_enabled()),
        ),
        ("CrbsConfig", "build_target", d::default_build_target()),
        (
            "CrbsConfig",
            "shared_layer_poll_interval_ms",
            d::default_shared_layer_poll_interval_ms().to_string(),
        ),
        (
            "CrbsConfig",
            "shared_layer_timeout_secs",
            d::default_shared_layer_timeout_secs().to_string(),
        ),
        (
            "CrbsConfig",
            "shared_layer_max_retries",
            d::default_shared_layer_max_retries().to_string(),
        ),
        (
            "CrbsConfig",
            "chain_parallelism",
            d::default_chain_parallelism().to_string(),
        ),
        (
            "CrbsConfig",
            "chain_max_recovery_rounds",
            d::default_chain_max_recovery_rounds().to_string(),
        ),
        (
            "CrbsConfig",
            "ccache_max_size",
            d::default_ccache_max_size(),
        ),
        (
            "CrbsConfig",
            "tmpfs_dir",
            d::default_tmpfs_dir().display().to_string(),
        ),
        ("CrbsConfig", "network", d::default_network().to_string()),
        // ── types.rs（RepoConfig 子 def 的 serde 默认）──
        (
            "RepoConfig",
            "enabled",
            t::default_repo_enabled().to_string(),
        ),
        (
            "RepoConfig",
            "gpgcheck",
            t::default_repo_gpgcheck().to_string(),
        ),
        (
            "RepoConfig",
            "priority",
            t::default_repo_priority().to_string(),
        ),
        ("RepoConfig", "cost", t::default_repo_cost().to_string()),
        // ── server.rs（ServerConfig 及其子 def 的 serde 默认）──
        (
            "LogSanitizationConfig",
            "redact_tokens",
            server::default_log_sanitization_redact_tokens().to_string(),
        ),
        ("ServerConfig", "listen", server::default_listen()),
        (
            "ServerConfig",
            "shutdown_timeout_secs",
            server::default_shutdown_timeout_secs().to_string(),
        ),
        (
            "ServerConfig",
            "build_timeout_secs",
            server::default_build_timeout_secs().to_string(),
        ),
        (
            "ServerConfig",
            "upload_max_size_mb",
            server::default_upload_max_size_mb().to_string(),
        ),
        (
            "ServerConfig",
            "min_free_disk_gb",
            server::default_min_free_disk_gb().to_string(),
        ),
        (
            "ServerConfig",
            "gc_result_retention",
            server::default_gc_result_retention().to_string(),
        ),
        (
            "ServerConfig",
            "db_retention_days",
            server::default_db_retention_days().to_string(),
        ),
        (
            "LocalConfig",
            "enable",
            server::default_local_enable().to_string(),
        ),
        (
            "LocalConfig",
            "daemon_auto",
            server::default_local_daemon_auto().to_string(),
        ),
        (
            "LocalConfig",
            "idle_timeout_secs",
            server::default_local_idle_timeout_secs().to_string(),
        ),
        (
            "ServerConfig",
            "low_priority_reserve_ratio",
            server::default_low_priority_reserve_ratio().to_string(),
        ),
        (
            "ServerConfig",
            "auth_enabled",
            server::default_auth_enabled().to_string(),
        ),
        // default_public_access 同源喂 view/logs/download 三个键，钉一个代表。
        (
            "PublicAccessConfig",
            "view",
            server::default_public_access().to_string(),
        ),
        (
            "ServerConfig",
            "web_ui_enabled",
            server::default_web_ui_enabled().to_string(),
        ),
        (
            "ServerConfig",
            "force_secure_cookies",
            server::default_force_secure_cookies().to_string(),
        ),
        (
            "ServerConfig",
            "allow_srpm_download",
            server::default_allow_srpm_download().to_string(),
        ),
        (
            "ServerConfig",
            "resource_profile_min_peak_rss_kb",
            server::default_resource_profile_min_peak_rss_kb().to_string(),
        ),
        (
            "ServerConfig",
            "resource_censor_headroom",
            server::default_resource_censor_headroom().to_string(),
        ),
        (
            "ServerConfig",
            "resource_profile_weights_enabled",
            server::default_resource_profile_weights_enabled().to_string(),
        ),
        (
            "ServerConfig",
            "resource_heavy_srpm_bytes",
            server::default_resource_heavy_srpm_bytes().to_string(),
        ),
        (
            "ServerConfig",
            "resource_dispatch_watermark_enabled",
            server::default_resource_dispatch_watermark_enabled().to_string(),
        ),
        (
            "ServerConfig",
            "resource_hard_req_stall_secs",
            server::default_resource_hard_req_stall_secs().to_string(),
        ),
        (
            "ServerConfig",
            "resource_mem_watermark",
            server::default_resource_mem_watermark().to_string(),
        ),
        (
            "ServerConfig",
            "resource_cpu_watermark",
            server::default_resource_cpu_watermark().to_string(),
        ),
    ];

    // 防漏登：写死表长测不出漏登——include_str! 计三源文件 `fn default_` 定义数，
    // 断言 表长 + 豁免数 == 源码计数（命中均为 serde 默认 fn，无测试/prose 命中）。
    let defaults_fns = include_str!("defaults.rs").matches("fn default_").count();
    let server_fns = include_str!("server.rs").matches("fn default_").count();
    let types_fns = include_str!("types.rs").matches("fn default_").count();
    // 豁免：default_ccache_dir（派生占位，真实默认 {crbs_root}/ccache/{product} 在 Config::load 算，
    // 无字面 "Default:" 可钉）；RemoteConfig::default_profile（运行时访问器非 serde 默认 fn，语义在 description）。
    const EXEMPT_FROM_TABLE: usize = 2;
    assert_eq!(
        cases.len() + EXEMPT_FROM_TABLE,
        defaults_fns + server_fns + types_fns,
        "default fn registration drifted: {} `fn default_` definitions in defaults.rs + \
         config/server.rs + types.rs vs {} registered + {EXEMPT_FROM_TABLE} exempt — register \
         the new default fn in the table above (or extend the exemption list with justification)",
        defaults_fns + server_fns + types_fns,
        cases.len(),
    );

    // 源码计数 55（defaults 25 + server 25 + types 5）− 2 豁免 = 53，写死防漂移。
    assert_eq!(
        cases.len(),
        53,
        "default fn registration count drifted (new default fn not registered here?)"
    );

    let schema = schema();
    let mut failures = Vec::new();
    for (def_name, key, expected) in &cases {
        let Some(def) = schema["$defs"].get(def_name) else {
            failures.push(format!("{def_name}.{key}: no such $def in schema"));
            continue;
        };
        let Some(prop) = def.get("properties").and_then(|p| p.get(key)) else {
            failures.push(format!("{def_name}.{key}: property missing from schema"));
            continue;
        };
        let desc = prop
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("");
        let needle = format!("Default: {expected}");
        if !desc.contains(&needle) {
            failures.push(format!(
                "{def_name}.{key}: description does not contain \"{needle}\" — schema prose \
                 drifted from the serde default fn value"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "schema Default prose drift:\n  {}",
        failures.join("\n  ")
    );
}

/// 防线 4 补丁：`#[serde(default)]` 裸 bool 没有 `fn default_` 可登记进上表，
/// 默认值文案只能靠结构体默认值对钉。resource 三个消费开关默认 false 是
/// 升级零变化的契约，任一处漂移都按失败处理。
#[test]
fn bare_bool_server_defaults_match_schema() {
    let cfg = crate::config::ServerConfig::default();
    let cases: &[(&str, bool)] = &[
        (
            "resource_requirements_enabled",
            cfg.resource_requirements_enabled,
        ),
        (
            "resource_local_watermark_enabled",
            cfg.resource_local_watermark_enabled,
        ),
        ("resource_steering_enabled", cfg.resource_steering_enabled),
        (
            "resource_learned_gates_enabled",
            cfg.resource_learned_gates_enabled,
        ),
    ];
    let schema = schema();
    let mut failures = Vec::new();
    for (key, actual) in cases {
        if *actual {
            failures.push(format!(
                "ServerConfig.{key}: serde default is {actual}, expected false"
            ));
        }
        let Some(prop) = schema["$defs"]["ServerConfig"]["properties"].get(*key) else {
            failures.push(format!("ServerConfig.{key}: property missing from schema"));
            continue;
        };
        let desc = prop
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !desc.contains("Default: false") {
            failures.push(format!(
                "ServerConfig.{key}: description does not contain \"Default: false\""
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "bare bool default drift:\n  {}",
        failures.join("\n  ")
    );
}

/// 防线 5：examples/config 样例文档每个键（顶层 + 嵌套对象键）必须在对应 def
/// 的 properties 中声明；方向"样例键 ⊆ schema"，schema 侧多写由防线 2 兜住。
/// WorkerConfig 结构体不在 crbs-core 可见，此测试是该 def 唯一的键名同步防线。
#[test]
fn example_config_keys_declared_in_schema() {
    let schema = schema();
    let examples = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/config");
    let cases: &[(&str, &str)] = &[
        ("fedora.toml", "ProductConfig"),
        ("worker.toml", "WorkerConfig"),
    ];

    let mut missing = Vec::new();
    for (file, def_name) in cases {
        let text = std::fs::read_to_string(examples.join(file))
            .unwrap_or_else(|e| panic!("read example config {file}: {e}"));
        let doc: Value = toml::from_str(&text)
            .unwrap_or_else(|e| panic!("example config {file} must parse as TOML: {e}"));
        check_paths(
            &doc,
            def_of(&schema, def_name),
            &format!("{def_name}."),
            &schema,
            &mut missing,
        );
    }
    assert!(
        missing.is_empty(),
        "schema drift: example config keys missing from config.schema.json properties \
         (add/fix the corresponding def properties):\n  {}",
        missing.join("\n  ")
    );
}

/// 必填键：WorkerConfig 的 name / hub_url / token 必须在 def 的 required 里。
/// ProductConfig 必填为双形态（根产品 base_packages+repos；子产品只写 '+field' 追加键），
/// 用 anyOf 而非顶层 required（会误拒合法子产品文件）；仓库无 JSON Schema 校验器，
/// 按结构断言三支 required 对应根产品与两种子产品形态、无一支为空——全空对象不匹配任何分支即被拒。
#[test]
fn required_keys_declared_in_schema() {
    let schema = schema();

    let worker_required: Vec<String> = schema["$defs"]["WorkerConfig"]["required"]
        .as_array()
        .unwrap_or_else(|| panic!("WorkerConfig def must carry a required array"))
        .iter()
        .map(|v| {
            v.as_str()
                .expect("required entries are strings")
                .to_string()
        })
        .collect();
    for key in ["name", "hub_url", "token"] {
        assert!(
            worker_required.iter().any(|k| k == key),
            "WorkerConfig.required must contain {key}"
        );
    }

    let any_of = schema["$defs"]["ProductConfig"]["anyOf"]
        .as_array()
        .unwrap_or_else(|| {
            panic!("ProductConfig def must express its required semantics via anyOf")
        });
    let branches: Vec<Vec<String>> = any_of
        .iter()
        .map(|branch| {
            branch["required"]
                .as_array()
                .expect("each anyOf branch carries a required array")
                .iter()
                .map(|v| {
                    v.as_str()
                        .expect("required entries are strings")
                        .to_string()
                })
                .collect()
        })
        .collect();
    assert!(
        branches.contains(&vec!["base_packages".to_string(), "repos".to_string()]),
        "anyOf must contain the root-product shape requiring both \
         base_packages and repos: {branches:?}"
    );
    for append_key in ["+base_packages", "+repos"] {
        assert!(
            branches.iter().any(|b| b.len() == 1 && b[0] == append_key),
            "anyOf must contain a child-product shape requiring only \
             '{append_key}': {branches:?}"
        );
    }
    assert!(
        branches.iter().all(|b| !b.is_empty()),
        "no anyOf branch may carry an empty required array — a fully empty \
         product file (neither root nor child shape) must match no branch \
         and be rejected: {branches:?}"
    );
}
