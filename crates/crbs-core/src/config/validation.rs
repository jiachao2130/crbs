// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 配置校验：架构、后端、资源上限与跨字段前置条件。

use crate::error::CrbsError;

/// 验证 build_target 只允许 bb/bs/ba。
pub(crate) fn validate_build_target(product: Option<&str>, global: &str) -> crate::Result<String> {
    let target = product.unwrap_or(global);
    if !matches!(target, "bb" | "bs" | "ba") {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "invalid build_target: '{}'. Only 'bb', 'bs', 'ba' are allowed",
                target
            ),
        });
    }
    Ok(target.to_string())
}

/// 确定性模式前置校验：须在配置合并后以**生效值**调用（`deterministic`
/// 产品级、另两项全局级）。`build_target = ba` 提交即拒（每架构重造 SRPM 引入
/// “哪个 SRPM 算数”的字节歧义，不自动降级）；`dnf_cache_enabled = false` 拒绝
/// 并给修复指引（无 dnf 缓存的 reproduce 链路无从核验，exit 4 教训）。同一规则在
/// fan_out_builds 与引擎 `with_build_stage` 另有运行时断言副本，防运行期改全局配置静默失锚。
pub fn validate_deterministic_preconditions(
    deterministic: bool,
    build_target: &str,
    dnf_cache_enabled: bool,
) -> crate::Result<()> {
    if !deterministic {
        return Ok(());
    }
    if build_target == "ba" {
        return Err(CrbsError::ValidationFailed {
            message: "deterministic product cannot use build_target 'ba': rebuilding the SRPM \
                 per-arch would make 'which SRPM counts' ambiguous and break byte-identical \
                 output; use 'bb' (canonical SRPM topology)"
                .to_string(),
        });
    }
    if !dnf_cache_enabled {
        return Err(CrbsError::ValidationFailed {
            message: "deterministic product requires dnf_cache_enabled = true: without a \
                 persistent dnf cache the provenance/reproduce chain cannot be verified \
                 (measured failure, exit 4). Fix: set 'dnf_cache_enabled = true' in the \
                 global config (crbs.toml) or the product config"
                .to_string(),
        });
    }
    Ok(())
}

/// 验证 backend 只允许 chroot/nspawn（`None` 落默认 "nspawn"）；规则本体在 [`crate::build_options::validate_backend_name`]。
pub(crate) fn validate_backend(backend: Option<&str>) -> crate::Result<String> {
    let name = backend.unwrap_or("nspawn");
    crate::build_options::validate_backend_name(name)?;
    Ok(name.to_string())
}

pub(crate) fn validate_memory_max_optional(value: Option<&str>) -> crate::Result<Option<String>> {
    if let Some(s) = value {
        validate_memory_max(s)?;
        Ok(Some(s.to_string()))
    } else {
        Ok(None)
    }
}

pub(crate) fn validate_cpu_quota_optional(value: Option<&str>) -> crate::Result<Option<String>> {
    if let Some(s) = value {
        validate_cpu_quota(s)?;
        Ok(Some(s.to_string()))
    } else {
        Ok(None)
    }
}

/// 校验 systemd MemoryMax= 格式：纯数字 + 可选 K/M/G/T 后缀；上限 16 TiB，防异常巨值在 nspawn 写入路径触发溢出/内核拒绝。
pub fn validate_memory_max(s: &str) -> crate::Result<()> {
    if s.is_empty()
        || !s
            .chars()
            .all(|c| c.is_ascii_digit() || c == 'K' || c == 'M' || c == 'G' || c == 'T')
    {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "invalid memory_max '{}'; expected like '512M' / '2G' / '0'",
                s
            ),
        });
    }
    let suffix_count = s.chars().filter(|c| !c.is_ascii_digit()).count();
    if suffix_count > 1 || (suffix_count == 1 && !s.ends_with(['K', 'M', 'G', 'T'].as_ref())) {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "invalid memory_max '{}'; expected like '512M' / '2G' / '0'",
                s
            ),
        });
    }
    if !s.chars().any(|c| c.is_ascii_digit()) {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "invalid memory_max '{}'; expected like '512M' / '2G' / '0'",
                s
            ),
        });
    }
    // "0" = 无限制仍放行；解析复用 nspawn 同一实现（checked_mul 溢出拒绝），校验与写入判定口径一致。
    const MAX_MEMORY_BYTES: u64 = 16 * 1024 * 1024 * 1024 * 1024;
    let bytes = crate::engine::backend::nspawn::parse::parse_memory_max(s)?;
    if bytes > MAX_MEMORY_BYTES {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "memory_max '{}' exceeds the {} TiB upper limit",
                s,
                MAX_MEMORY_BYTES / (1024 * 1024 * 1024 * 1024)
            ),
        });
    }
    Ok(())
}

/// memory_max 字符串 → KB（u64 字节整除 1024）：hub 侧 cap-OOM 判定用，与
/// nspawn 写入路径同一解析实现（validate/parse 同源）。截断损失 < 1KB，相对
/// 0.9×cap 阈值可忽略；"0"（无限制）返回 0，调用方按"未设 cap"处理。
pub fn parse_memory_max_kb(s: &str) -> crate::Result<i64> {
    let bytes = crate::engine::backend::nspawn::parse::parse_memory_max(s)?;
    i64::try_from(bytes / 1024).map_err(|_| CrbsError::ValidationFailed {
        message: format!("memory_max '{s}' exceeds i64 KB range"),
    })
}

/// 资源下限尺寸串 → KB（`min_mem` / `min_disk` 共用）：`K/M/G/T` 后缀按 1024
/// 基（`'4G'` = 4 GiB），纯数字按 KB（与 memory_max 的裸数字=字节语义不同，
/// 下限声明面向人，提交口径即存储口径）；0/负值/坏单位/溢出在此拒绝，正值与
/// 字段级上界（mem≤1TiB / disk≤64TiB）由 validate_options 按字段收口。
/// `field` 进错误文案点名字段（"invalid min_mem ..."）。
pub fn parse_resource_min_kb(field: &str, raw: &str) -> crate::Result<i64> {
    let s = raw.trim();
    let invalid = || CrbsError::ValidationFailed {
        message: format!(
            "invalid {field} '{}'; expected like '4G' / '512M' / '2097152' \
             (K/M/G/T = 1024-based, bare digits = KB, must be > 0)",
            truncate_for_error(s)
        ),
    };
    // find + split_at 保留两段（split_once 对谓词 pattern 的尾段行为不可靠）；
    // None = 空串或纯数字，Some(0) = 首字符非数字（负号/裸单位等）。
    let (digits, unit) = match s.find(|c: char| !c.is_ascii_digit()) {
        None => (s, ""),
        Some(idx) => {
            let (d, u) = s.split_at(idx);
            if !matches!(u, "K" | "M" | "G" | "T") || d.is_empty() {
                return Err(invalid());
            }
            (d, u)
        }
    };
    let value: u64 = digits.parse().map_err(|_| invalid())?;
    if value == 0 {
        return Err(CrbsError::ValidationFailed {
            message: format!("invalid {field} '{s}': must be > 0"),
        });
    }
    // 单位 → KB 因子（1024 基；结果单位是 KB 不是字节）。
    let factor: u64 = match unit {
        "" => 1,
        "K" => 1,
        "M" => 1024,
        "G" => 1024 * 1024,
        _ => 1024 * 1024 * 1024, // "T"
    };
    let kb = value.checked_mul(factor).ok_or_else(invalid)?;
    i64::try_from(kb).map_err(|_| invalid())
}

/// 错误回显长度上限（本文件口径）：超长输入只回显前 64 字符。
fn truncate_for_error(text: &str) -> &str {
    text.char_indices()
        .take(64)
        .last()
        .map(|(i, c)| &text[..i + c.len_utf8()])
        .unwrap_or(text)
}

/// 校验 `ccache -M SIZE` 格式：数字 + 单位（`K`/`k`/`M`/`G`/`T`，可选 `i` 与 `B`/`b`
/// 后缀）。单位集对齐 ccache 解析器（util/string.cpp `parse_size`）：小写 `g`/`m`/`t`
/// 被 ccache 拒绝，`ccache -M '4g'` 失败后经 pipeline `|| warn` 静默降级为无上限
/// 缓存（本校验要堵的洞）；`i`、`B`/`b` ccache 不检查，放行。有意收紧：裸数字拒绝
///（ccache 默认按 GiB 解释）；0 拒绝（`-M 0` = 无限制；未配置回落全局默认 “4G”）。
pub(crate) fn validate_ccache_max_size(s: &str) -> crate::Result<()> {
    let invalid = || CrbsError::ValidationFailed {
        message: format!(
            "invalid ccache_max_size '{s}'; expected digits + unit \
                 (K/k/M/G/T, optional i/B suffix) like '512M' / '4G' / '2GiB'"
        ),
    };
    // find + split_at 保留两段（split_once 吞分隔符会丢单位字母）；None = 空串
    // 或纯数字，Some(0) = 首字符非数字（空白/负号/裸单位）。
    let (digits, rest) = match s.find(|c: char| !c.is_ascii_digit()) {
        None | Some(0) => return Err(invalid()),
        Some(idx) => s.split_at(idx),
    };
    // u64 溢出的天文数字同样按坏格式拒绝（ccache 内部按字节 uint64 换算）
    if digits.parse::<u64>().map_err(|_| invalid())? == 0 {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "invalid ccache_max_size '{s}': 0 would disable the cache size limit; \
                 leave it unset to fall back to the global default"
            ),
        });
    }
    let mut chars = rest.chars();
    match chars.next() {
        // 裸数字拒绝（ccache 默认按 GiB 解释，要求显式单位）
        None => Err(invalid()),
        Some('K' | 'k' | 'M' | 'G' | 'T') => {
            // 可选 i（二进制标记）+ 可选 B/b，之后必须结束
            match (chars.next(), chars.next()) {
                (None, None) => Ok(()),
                (Some('i'), None) => Ok(()),
                (Some('B' | 'b'), None) => Ok(()),
                (Some('i'), Some('B' | 'b')) if chars.next().is_none() => Ok(()),
                _ => Err(invalid()),
            }
        }
        Some(_) => Err(invalid()),
    }
}

/// 校验 systemd CPUQuota= 格式：纯数字 + 可选 % 后缀；上限 cores ≤ 1024、
/// percent ≤ 10000（100 核）；"0"/"0%" 拒绝（quota=0 是内核 EINVAL，
/// 无限制应不配置 cpu_quota）。
pub fn validate_cpu_quota(s: &str) -> crate::Result<()> {
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_digit() || c == '%') {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "invalid cpu_quota '{}'; expected like '200%' (2 cores) / '50%' (half)",
                s
            ),
        });
    }
    let pct_count = s.chars().filter(|c| *c == '%').count();
    if pct_count > 1 || (pct_count == 1 && !s.ends_with('%')) {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "invalid cpu_quota '{}'; expected like '200%' (2 cores) / '50%' (half)",
                s
            ),
        });
    }
    // 裸 "%" 数字部分为空，systemd 亦拒绝，此处同拒
    if !s.chars().any(|c| c.is_ascii_digit()) {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "invalid cpu_quota '{}'; expected like '200%' (2 cores) / '50%' (half)",
                s
            ),
        });
    }
    const MAX_CORES: u64 = 1024;
    const MAX_PERCENT: u64 = 10000;
    if let Some(pct_str) = s.strip_suffix('%') {
        let pct: u64 = pct_str.parse().map_err(|_| CrbsError::ValidationFailed {
            message: format!("invalid cpu_quota '{}'; percentage part must fit in u64", s),
        })?;
        if pct == 0 || pct > MAX_PERCENT {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "cpu_quota '{}' out of range: percent must be 1..={}",
                    s, MAX_PERCENT
                ),
            });
        }
    } else {
        let cores: u64 = s.parse().map_err(|_| CrbsError::ValidationFailed {
            message: format!("invalid cpu_quota '{}'; cores part must fit in u64", s),
        })?;
        if cores == 0 || cores > MAX_CORES {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "cpu_quota '{}' out of range: cores must be 1..={}",
                    s, MAX_CORES
                ),
            });
        }
    }
    Ok(())
}

/// 校验配置数值必须 > 0，防止用户把 0 当成“不限制”而导致误删全部缓存/结果。
pub(crate) fn require_positive_u64(name: &str, value: u64) -> crate::Result<()> {
    if value == 0 {
        return Err(CrbsError::ValidationFailed {
            message: format!("invalid {}: 0; must be > 0 when configured", name),
        });
    }
    Ok(())
}

/// 校验 u64 时间参数（days/hours/secs）可安全转 i64：值以 i64 进 SQL 时间运算，
/// ≥ 2^63 `as i64` 回绕成负数使 "N 天前" 变未来时刻、retention GC 匹配所有行
///（毁灭性删除）→ 加载期拒绝；调用侧另有 `util::u64_to_i64_saturating` 饱和兜底。
pub(crate) fn require_i64_representable_u64(name: &str, value: u64) -> crate::Result<()> {
    if value > i64::MAX as u64 {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "invalid {}: {}; exceeds i64::MAX and would wrap negative in SQL time arithmetic",
                name, value
            ),
        });
    }
    Ok(())
}

pub(crate) fn require_positive_usize(name: &str, value: usize) -> crate::Result<()> {
    if value == 0 {
        return Err(CrbsError::ValidationFailed {
            message: format!("invalid {}: 0; must be > 0 when configured", name),
        });
    }
    Ok(())
}

/// 产品名校验：委托 [`crate::validation::validate_product`]（ASCII-only `[a-zA-Z0-9_-]`）。
pub(crate) fn validate_product_name(product: &str) -> crate::Result<()> {
    crate::validation::validate_product(product)
}

/// 校验 repo name：值拼进 dnf `--repofrompath`/`--setopt`，逗号/空白截断拆裂参数、
/// 冒号/等号混淆 setopt 解析；允许 `[A-Za-z0-9_.-]`（repo id 惯例含点，如 `openEuler-24.03`）。
pub(crate) fn validate_repo_name(name: &str) -> crate::Result<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "invalid repo name '{}': only [A-Za-z0-9_.-] are allowed \
                 (comma/space/colon would break dnf --repofrompath/--setopt)",
                name
            ),
        });
    }
    Ok(())
}

/// 校验 [`crate::config::RepoConfig`] 全部自由文本字段：DB chain-resolve 出口
///（state/product_resolve.rs）point-of-use 校验，`name` 与文件加载路径同口径。
/// - `name`：`[A-Za-z0-9_.-]` 白名单，路径分隔符 / `..` 穿越天然被拒（值拼进
///   `repo_dir.join("{name}.repo")` 与 dnf `--repofrompath/--setopt`）；
/// - `baseurl`/`gpgkey`/`exclude[]`/`includepkgs[]`/`extra` 键值拒控制字符
///   （含 `\n` `\r` `\0`）：原样写入 chroot 内 `.repo` 文件，换行可注入 dnf
///   指令（如 `gpgcheck=0`）；baseurl/gpgkey 镜像文件端“非空 + 无控制字符”，
///   不做 scheme 校验、不单方加严致两端分叉；
/// - `exclude[]`/`includepkgs[]` 另拒空格/逗号：查询期 `.repo` 按空格 join、
///   构建期 `--setopt` 按逗号 join，含之则两端过滤语义静默分叉。
pub(crate) fn validate_repo_config(repo: &crate::config::RepoConfig) -> crate::Result<()> {
    validate_repo_name(&repo.name)?;
    if repo.baseurl.is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: format!("repo '{}' has empty baseurl", repo.name),
        });
    }
    reject_control_chars(&repo.baseurl, &repo.name, "baseurl")?;
    if let Some(gpgkey) = &repo.gpgkey {
        reject_control_chars(gpgkey, &repo.name, "gpgkey")?;
    }
    for (field, list) in [
        ("exclude", &repo.exclude),
        ("includepkgs", &repo.includepkgs),
    ] {
        for pkg in list {
            reject_control_chars(pkg, &repo.name, field)?;
            reject_space_comma(pkg, &repo.name, field)?;
        }
    }
    if let Some(extra) = &repo.extra {
        // 逐行校验（\n 是 extra 合法行分隔符）：注释/空行跳过，其余与 url.rs parse_extra_lines 同口径拆 key=value 校验键与值。
        for line in extra.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                reject_control_chars(key.trim(), &repo.name, "extra key")?;
                reject_control_chars(value.trim(), &repo.name, "extra value")?;
            } else {
                reject_control_chars(line, &repo.name, "extra line")?;
            }
        }
    }
    Ok(())
}

/// 字段值含控制字符 → `ValidationFailed`，消息带 repo 名与字段名（可定位）。
fn reject_control_chars(value: &str, repo_name: &str, field: &str) -> crate::Result<()> {
    if value.chars().any(|c| c.is_control()) {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "repo '{}' field '{}' contains control characters \
                 (newline/CR/NUL would inject .repo directives): {:?}",
                repo_name, field, value
            ),
        });
    }
    Ok(())
}

/// exclude/includepkgs 条目空格/逗号 → 拒绝（`.repo` 按空格 join、`--setopt` 按逗号 join，两端会静默分叉）。
fn reject_space_comma(value: &str, repo_name: &str, field: &str) -> crate::Result<()> {
    if value.contains(' ') || value.contains(',') {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "repo '{}' field '{}' entry must not contain spaces or commas \
                 (.repo files join entries with spaces, dnf --setopt with commas; \
                 such globs would silently diverge between query and build): {:?}",
                repo_name, field, value
            ),
        });
    }
    Ok(())
}

/// 校验 Unix 用户名格式：首字符字母/下划线，后续 `[a-zA-Z0-9_-]`，长度 ≤ 32
///（覆盖 useradd 默认限制，防 sudoers 注入/损坏）。
pub(crate) fn validate_unix_name(name: &str, field: &str) -> crate::Result<()> {
    const MAX_LEN: usize = 32;
    if name.is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: format!("{} cannot be empty", field),
        });
    }
    if name.len() > MAX_LEN {
        return Err(CrbsError::ValidationFailed {
            message: format!("{} '{}' exceeds {} characters", field, name, MAX_LEN),
        });
    }
    let mut chars = name.chars();
    // 空串已在上面拦截，此分支不可达；用 let-else 避免 unwrap。
    let Some(first) = chars.next() else {
        return Err(CrbsError::ValidationFailed {
            message: format!("{} cannot be empty", field),
        });
    };
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "{} '{}' must start with a letter or underscore",
                field, name
            ),
        });
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "{} '{}' contains invalid characters; only [a-zA-Z0-9_-] are allowed",
                field, name
            ),
        });
    }
    Ok(())
}

/// 解析 SharedLayer 过期时间：空/纯空白 → `None`（由 shared_layer TTL 侧回落
/// 缺省 7 天，见 `defaults::default_shared_layer_staleness`）；后缀 `d`/`h`/`m`/`s`
///（天/时/分/秒），不区分大小写。
/// Option 路径字段就地规范化校验：`Some` 时经 [`validate_config_path`]
/// 归一回写，`None` 不动；字段名进错误消息。
pub(crate) fn validate_opt_path(
    cfg_path: &mut Option<std::path::PathBuf>,
    name: &str,
) -> crate::Result<()> {
    if let Some(p) = cfg_path.clone() {
        *cfg_path = Some(validate_config_path(&p, name)?);
    }
    Ok(())
}

pub(crate) fn parse_staleness(s: &str) -> crate::Result<Option<std::time::Duration>> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    // 末字符须为单位、前缀须非空正整数；按字符切而非 split_at(len-1)：多字节末
    // 字符（如 "7天"）不在 UTF-8 边界会 panic，非 ASCII 单位走 unknown unit 拒绝。
    let (num_part, unit) = match trimmed
        .chars()
        .next_back()
        .and_then(|u| trimmed.strip_suffix(u).map(|n| (n, u)))
    {
        Some((n, u)) if !n.is_empty() => (n, u),
        _ => {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "invalid shared_layer_staleness '{}': expected format like '7d', '24h', '30m', '3600s'",
                    s
                ),
            });
        }
    };
    let value: u64 = num_part.parse().map_err(|_| CrbsError::ValidationFailed {
        message: format!(
            "invalid shared_layer_staleness '{}': expected positive integer before unit",
            s
        ),
    })?;

    let seconds = match unit.to_ascii_lowercase() {
        'd' => value.checked_mul(24 * 60 * 60),
        'h' => value.checked_mul(60 * 60),
        'm' => value.checked_mul(60),
        's' => Some(value),
        _ => {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "invalid shared_layer_staleness '{}': unknown unit '{}'",
                    s, unit
                ),
            })
        }
    };

    let seconds = seconds.ok_or_else(|| CrbsError::ValidationFailed {
        message: format!("shared_layer_staleness '{}' overflows u64", s),
    })?;

    if seconds == 0 {
        return Ok(None);
    }

    // TTL 判定走 `as_secs() as i64`（engine/shared_layer/ttl.rs）：≥ 2^63 秒会
    // 回绕成负数，层永远判定为 stale（重建风暴）。这里按 i64::MAX 秒封顶拒绝。
    if seconds > i64::MAX as u64 {
        return Err(CrbsError::ValidationFailed {
            message: format!("shared_layer_staleness '{}' exceeds i64::MAX seconds", s),
        });
    }

    Ok(Some(std::time::Duration::from_secs(seconds)))
}

/// 校验配置目录（`CRBS_CONFIG_DIR` / `--config-dir`）必须为非空绝对路径：
/// 相对/空路径使配置解析依赖进程 CWD（cron / systemd 下不可预测）。
pub fn validate_config_dir(dir: &std::path::Path) -> crate::Result<()> {
    if dir.as_os_str().is_empty() || !dir.is_absolute() {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "config dir must be a non-empty absolute path: {}",
                dir.display()
            ),
        });
    }
    Ok(())
}

/// 校验配置路径：必须为绝对路径；`..` 弹出空栈（逃逸根）即拒。返回去 `.`/`..` 后的规范化路径。
pub fn validate_config_path(
    path: &std::path::Path,
    name: &str,
) -> crate::Result<std::path::PathBuf> {
    if !path.is_absolute() {
        return Err(CrbsError::ValidationFailed {
            message: format!("{} must be an absolute path: {}", name, path.display()),
        });
    }
    let mut out = std::path::PathBuf::new();
    for c in path.components() {
        match c {
            std::path::Component::RootDir => out.push("/"),
            std::path::Component::Normal(p) => out.push(p),
            std::path::Component::ParentDir => {
                if !out.pop() {
                    return Err(CrbsError::ValidationFailed {
                        message: format!("{} escapes filesystem root: {}", name, path.display()),
                    });
                }
            }
            // CurDir（"."）丢弃；Prefix 仅 Windows 盘符产生，Linux + 绝对路径下不可达，忽略。
            std::path::Component::CurDir | std::path::Component::Prefix(_) => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 非 deterministic 一律放行（含 ba / 无 dnf_cache 坏组合）。
    #[test]
    fn deterministic_preconditions_pass_when_disabled() {
        assert!(validate_deterministic_preconditions(false, "ba", false).is_ok());
        assert!(validate_deterministic_preconditions(false, "bb", false).is_ok());
    }

    /// deterministic + build_target=ba 提交即拒，报错须指明修复方向（bb）；bb/bs 放行。
    #[test]
    fn deterministic_rejects_ba_target() {
        let err = validate_deterministic_preconditions(true, "ba", true).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ba"), "got: {msg}");
        assert!(msg.contains("'bb'"), "must point at the fix (bb): {msg}");
        assert!(validate_deterministic_preconditions(true, "bb", true).is_ok());
        assert!(validate_deterministic_preconditions(true, "bs", true).is_ok());
    }

    /// deterministic 缺 dnf_cache_enabled 报错，修复指引指名配置键与配置文件。
    #[test]
    fn deterministic_requires_dnf_cache() {
        let err = validate_deterministic_preconditions(true, "bb", false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("dnf_cache_enabled"), "got: {msg}");
        assert!(
            msg.contains("crbs.toml"),
            "must point at the fix (global config): {msg}"
        );
        assert!(validate_deterministic_preconditions(true, "bb", true).is_ok());
    }

    /// 单位解析矩阵：K/M/G/T 1024 基（'4G' = 4 GiB KB 数）、纯数字 = KB、
    /// 周边空白容忍；坏值（负号/小数/坏单位/双单位/裸单位/空/0）拒绝并点名字段。
    #[test]
    fn parse_resource_min_kb_unit_matrix() {
        let kb = |s: &str| parse_resource_min_kb("min_mem", s).unwrap();
        assert_eq!(kb("2097152"), 2 * 1024 * 1024); // 纯数字 = KB
        assert_eq!(kb("2048K"), 2048); // 2048 KiB = 2048 KB
        assert_eq!(kb("2048M"), 2048 * 1024); // 2 GiB
        assert_eq!(kb("4G"), 4 * 1024 * 1024); // '4G' = 4 GiB
        assert_eq!(kb("2T"), 2 * 1024 * 1024 * 1024);
        assert_eq!(kb(" 4G "), 4 * 1024 * 1024); // trim 容忍表单空白
        for bad in [
            "-4G", "4.5G", "4Gi", "4GB", "4X", "GG", "G", "4K4M", "", "0", "00",
        ] {
            let err = parse_resource_min_kb("min_disk", bad).unwrap_err();
            let msg = err.to_string();
            assert!(
                matches!(&err, CrbsError::ValidationFailed { .. }),
                "{bad:?} must be ValidationFailed"
            );
            assert!(msg.contains("min_disk"), "error must name the field: {msg}");
        }
        // 溢出拒绝（u64/i64 均不回绕）。
        assert!(parse_resource_min_kb("min_mem", "999999999999999999999G").is_err());
    }
}
