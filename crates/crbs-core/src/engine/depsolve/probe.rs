// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! SRPM header 探测与提取：replay 参数探测、BuildRequires / ARCH 的
//! 单包与批量（rpm -qp）查询。

use std::path::{Path, PathBuf};

use tokio_util::sync::CancellationToken;

use crate::error::CrbsError;

/// `rpm -qp` 批量查询每批最多 SRPM 数：Linux `ARG_MAX` 通常 2 MB，512 个路径按
/// 4 KB 上限估算即逼近上限；实际路径远短于 4 KB，512 安全且显著减少进程启动。
const RPM_QP_BATCH_SIZE: usize = 512;

/// 批量解析 BR+ARCH 时用来分隔不同 SRPM 输出的标记。
const BR_ARCH_BATCH_SEPARATOR: &str = "__CRBS_BR_ARCH_BATCH_SEPARATOR__";
const BR_BATCH_END_MARKER: &str = "__CRBS_BR_BATCH_END_MARKER__";

/// SRPM 头架构约束（spec `ExclusiveArch:` / `ExcludeArch:` 的打包期评估值，
/// 由 `rpm -qp` 数组形态标签读取，无需解析 spec 文本）。空 = 无该约束。
///
/// 已知边界：rich boolean 形态（`ExclusiveArch: %{x86_64}` 等）在 SRPM header
/// 中是未展开的单串，等值比较不命中；这类 spec 会被保守放行，由构建期
/// rpmbuild 权威裁决。报错文案点名实际取值，足以诊断。
///
/// 实测口径（rpm 6.0.2）：
/// queryformat 里 `[...]` 是数组迭代语法，方括号本身不落输出：输出行形态是
/// `EXCL=<空格分隔值>`（标签缺失时迭代 0 次 = `EXCL=` 空值；标量形态才输出
/// `(none)`，是解析陷阱，`parse_constraint_field` 防御性归一为空集）。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ArchConstraints {
    /// `ExclusiveArch` 评估值（空 = 无排他约束）。
    pub exclusive: Vec<String>,
    /// `ExcludeArch` 评估值（空 = 无排除约束）。
    pub exclude: Vec<String>,
}

impl ArchConstraints {
    /// 具体架构 target 的不兼容原因（校验对象 = rpmbuild 实际
    /// target，对具体架构包即派发/请求架构）。返回 `Some(原因)` = 不兼容，
    /// 原因文案点名约束来源与取值（响应/报错展示用）。两侧消费方
    /// （crbs-server `plan_srpm_arches`、CLI 本地预检）共用本实现，
    /// 语义漂移由各自单测矩阵钉住。
    ///
    /// 比对为逐字精确匹配，镜像 rpmbuild 的字面裁决（构建容器
    /// rpm 4.18.2 实测）：`ExclusiveArch: x86_64_v3` + target
    /// `x86_64` 拒（Architecture is not included）、`ExcludeArch: x86_64` +
    /// target `x86_64_v3` 放行（产物 arch 字面 `x86_64_v3`）；rpm 6.0.2
    /// 同为精确匹配。微架构变体与基础架构互不归属——将来 rpm 若引入
    /// 官方家族语义，需凭实测记录与钉死的版本号再引入归一。
    pub fn concrete_incompatible(&self, arch: &str) -> Option<String> {
        if !self.exclusive.is_empty() && !self.exclusive.iter().any(|a| a == arch) {
            Some(format!(
                "not in ExclusiveArch [{}]",
                self.exclusive.join(" ")
            ))
        } else if self.exclude.iter().any(|a| a == arch) {
            Some(format!(
                "excluded by ExcludeArch [{}]",
                self.exclude.join(" ")
            ))
        } else {
            None
        }
    }

    /// noarch target 的宿主代理检查（rpm 6.0.2 实测）：ExclusiveArch
    /// 对 noarch target 豁免；ExcludeArch 的检查对象是构建宿主架构——提交期
    /// 以派发架构（= worker 绑定架构）为宿主代理。比对逐字精确匹配
    /// （与 [`Self::concrete_incompatible`] 同口径）。
    pub fn noarch_host_incompatible(&self, host: &str) -> Option<String> {
        if self.exclude.iter().any(|a| a == host) {
            Some(format!(
                "excluded by ExcludeArch [{}] (noarch build host)",
                self.exclude.join(" ")
            ))
        } else {
            None
        }
    }

    /// 按 srpm_arch（SRPM header ARCH）分派检查原语："noarch" 走
    /// [`Self::noarch_host_incompatible`]（`arch` 作宿主代理），其余走
    /// [`Self::concrete_incompatible`]。server 批次 plan、server submit、
    /// CLI 本地预检三处共用，分派规则漂移由单测矩阵钉住。
    pub fn incompatible_for(&self, srpm_arch: &str, arch: &str) -> Option<String> {
        if srpm_arch == "noarch" {
            self.noarch_host_incompatible(arch)
        } else {
            self.concrete_incompatible(arch)
        }
    }
}

/// 单包 BR+ARCH 探测结果：header ARCH、过滤后的 BuildRequires、架构约束。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SrpmBrArch {
    /// header ARCH（空串 = 探测失败）。
    pub arch: String,
    /// BuildRequires（`rpmlib(` 条目已过滤）。
    pub build_requires: Vec<String>,
    /// ExclusiveArch/ExcludeArch 评估值（空 = 无该约束）。
    pub arch_constraints: ArchConstraints,
}

/// rpm -qp / rpmspec 本地头/规格查询的兜底超时：停滞存储上挂死的 rpm 不得无限
/// 占用构建 future——server submit 路径 `cancel_token=None`，超时是唯一终止维度；
/// 批量 chunk 与单包 fallback 同值，批量超时后逐包重试会把 60s 放大成 N × 60s。
pub(super) const RPM_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// `probe_srpm_replay_params` 的 queryformat（标签必须带花括号）：rpm 对坏格式
///（如缺花括号的 `%TAG`）报 `incorrect format: invalid field width` 却仍退出 0、
/// stdout 为空——空输出按"标签缺失"处理会静默空转。防线：格式串钉死花括号形态
///（本常量 + 单测钉），成功但整行空输出按硬错误拒（见 [`parse_srpm_replay_params`]）。
const SRPM_REPLAY_QUERY_FORMAT: &str = "%{BUILDHOST}\t%{BUILDTIME}\n";

/// 单包 `rpm -qp` 样板：capped + 取消 + 超时执行，非零退出拒绝。`label`
/// 同时用于 spawn 上下文与错误文案；`corrupt_hint` 给失败信息追加坏包提示
///（replay 探测语义）。Cancelled 原样透传，不得包装成 DepsolveFailed。
async fn rpm_qp_single(
    srpm: &Path,
    queryformat: &str,
    label: &'static str,
    corrupt_hint: bool,
    cancel_token: Option<&CancellationToken>,
) -> crate::Result<std::process::Output> {
    let mut cmd = tokio::process::Command::new("rpm");
    cmd.arg("-qp")
        .arg("--queryformat")
        .arg(queryformat)
        .arg(srpm);
    let spawn_context = format!("spawn rpm -qp {label}");
    let output = crate::engine::command::run_command_capped_output_with_cancel_and_timeout(
        cmd,
        &spawn_context,
        cancel_token,
        RPM_QUERY_TIMEOUT,
    )
    .await
    .map_err(|e| match e {
        CrbsError::Cancelled => CrbsError::Cancelled,
        other => CrbsError::DepsolveFailed {
            message: format!("rpm -qp {label} for {}: {}", srpm.display(), other),
        },
    })?;
    if !output.status.success() {
        let hint = if corrupt_hint { " (corrupt SRPM?)" } else { "" };
        return Err(CrbsError::DepsolveFailed {
            message: format!(
                "rpm -qp {label} failed for {}: {}{hint}",
                srpm.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        });
    }
    Ok(output)
}

/// 从 SRPM 头探测 repro-from-srpm 回放参数（`BUILDHOST` + `BUILDTIME`）：
/// 单次 `rpm -qp`（queryformat 见 `SRPM_REPLAY_QUERY_FORMAT`），cancel 兼容 +
/// 60s 超时。取值语义（不降级不拒绝）：标签缺失（`(none)`）或字段空 = `None`；
/// 成功但整行空输出 = 坏格式/坏 rpm，非"标签缺失" → 硬错误；`BUILDTIME` 非整数
///（损坏头，提交期 400）或命令失败 → 硬错误（SRPM 损坏，与 arch 探测同语义）。
pub async fn probe_srpm_replay_params(
    srpm: &Path,
    cancel_token: Option<&CancellationToken>,
) -> crate::Result<(Option<String>, Option<i64>)> {
    let output = rpm_qp_single(
        srpm,
        SRPM_REPLAY_QUERY_FORMAT,
        "BUILDHOST/BUILDTIME",
        true,
        cancel_token,
    )
    .await?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_srpm_replay_params(stdout.trim()).map_err(|e| CrbsError::DepsolveFailed {
        message: match e {
            ProbeOutputError::Empty => format!(
                "rpm -qp BUILDHOST/BUILDTIME for {} returned empty output despite \
                 exit success (bad queryformat or corrupt RPM?)",
                srpm.display()
            ),
            ProbeOutputError::NonIntegerBuildTime(_) => format!(
                "rpm -qp BUILDHOST/BUILDTIME for {} returned non-integer BUILDTIME: \
                 {:?} (corrupt header?)",
                srpm.display(),
                stdout.trim()
            ),
        },
    })
}

/// probe 输出的解析失败形态（纯函数可单测）。
#[derive(Debug, PartialEq, Eq)]
enum ProbeOutputError {
    /// 整行空输出：坏格式/坏输入（rpm 对坏 queryformat 仍退出 0、stdout 为空），
    Empty,
    /// BUILDTIME 字段有值但不是整数（损坏头）。
    NonIntegerBuildTime(String),
}

/// 解析 `probe_srpm_replay_params` 的单行输出 `host\t<epoch>`（纯函数，可单测）：
/// 整行 trim 后空 → [`ProbeOutputError::Empty`]（调用方升级硬错误）。host：
/// `(none)`/空 → `None`，否则原样保留（rpm 头值无字符集保证）；time：`(none)`/空
/// → `None`，非整数 → [`ProbeOutputError::NonIntegerBuildTime`]（坏输入不降级）。
fn parse_srpm_replay_params(raw: &str) -> Result<(Option<String>, Option<i64>), ProbeOutputError> {
    if raw.trim().is_empty() {
        return Err(ProbeOutputError::Empty);
    }
    let mut fields = raw.splitn(2, '\t');
    let host_field = fields.next().unwrap_or("").trim();
    let time_field = fields.next().unwrap_or("").trim();
    let host = match host_field {
        "" | "(none)" => None,
        h => Some(h.to_string()),
    };
    let time = match time_field {
        "" | "(none)" => None,
        t => match t.parse::<i64>() {
            Ok(v) => Some(v),
            Err(_) => return Err(ProbeOutputError::NonIntegerBuildTime(t.to_string())),
        },
    };
    Ok((host, time))
}

/// 从 SRPM 直接提取 BuildRequires（不依赖 rpmspec；SRPM 的 Requires ≡
/// BuildRequires，输出 `name op version` 与 `resolve_deps_to_pkgs` 的
/// 消费方式兼容）。薄封装：内部调用 `parse_br_and_arch_from_srpm` 取 BR 部分。
pub async fn parse_build_requires_from_srpm(srpm: &Path) -> crate::Result<Vec<String>> {
    parse_br_and_arch_from_srpm(srpm, None)
        .await
        .map(|meta| meta.build_requires)
}

/// 从 SRPM header 读产物 ARCH（"noarch" / "x86_64" / ...）：纯 noarch 包返回
/// "noarch"，混合/纯 arch 包返回打包机架构；失败返回空串（调用方保守按 arch
/// 处理）。`cancel_token` + 60s 超时兜底（见 `RPM_QUERY_TIMEOUT`）。
pub async fn parse_arch_from_srpm(
    srpm: &Path,
    cancel_token: Option<&CancellationToken>,
) -> crate::Result<String> {
    let output = rpm_qp_single(srpm, "%{ARCH}", "ARCH", false, cancel_token).await?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// ARCH+架构约束单包 queryformat（与 [`SRPM_BR_ARCH_QUERY_FORMAT`] 同约束行
/// 协议，不含 BR 块）。尾随 `\n` 必须保留：rpm 按包连续渲染格式串，缺尾换行
/// 下一包的 ARCH 会黏到上一包 EXCLD 行（批量 3 行/SRPM 对账依赖独立行）。
const SRPM_ARCH_CONSTRAINTS_QUERY_FORMAT: &str =
    "%{ARCH}\nEXCL=[%{EXCLUSIVEARCH} ]\nEXCLD=[%{EXCLUDEARCH} ]\n";

/// 从 SRPM header 同时读 ARCH + 架构约束（单包；submit 期预检用，与
/// [`parse_arch_from_srpm`] 同超时/取消口径）。解析失败保守由调用方决定
/// （预检语义：探测失败 = 无约束信息，不拦截）。
pub async fn parse_arch_and_constraints_from_srpm(
    srpm: &Path,
    cancel_token: Option<&CancellationToken>,
) -> crate::Result<(String, ArchConstraints)> {
    let output = rpm_qp_single(
        srpm,
        SRPM_ARCH_CONSTRAINTS_QUERY_FORMAT,
        "ARCH+CONSTRAINTS",
        false,
        cancel_token,
    )
    .await?;
    let raw = String::from_utf8_lossy(&output.stdout);
    let mut lines = raw.lines().map(|l| l.to_string());
    let arch = lines
        .next()
        .map(|l| l.trim().to_string())
        .unwrap_or_default();
    let (_, constraints) = parse_br_arch_constraints_lines(lines);
    Ok((arch, constraints))
}

/// 批量从 SRPM header 读 ARCH + 架构约束：分批/单包回退/超时取消口径同
/// [`parse_arch_from_srpms`]，返回顺序与输入一致。
pub async fn parse_arch_and_constraints_from_srpms(
    srpms: &[PathBuf],
    cancel_token: Option<&CancellationToken>,
) -> Vec<crate::Result<(String, ArchConstraints)>> {
    let mut results = Vec::with_capacity(srpms.len());
    if srpms.is_empty() {
        return results;
    }
    for chunk in srpms.chunks(RPM_QP_BATCH_SIZE) {
        results.extend(parse_arch_constraints_chunk(chunk, cancel_token).await);
    }
    results
}

async fn parse_arch_constraints_chunk(
    chunk: &[PathBuf],
    cancel_token: Option<&CancellationToken>,
) -> Vec<crate::Result<(String, ArchConstraints)>> {
    let mut cmd = tokio::process::Command::new("rpm");
    cmd.arg("-qp")
        .arg("--queryformat")
        .arg(SRPM_ARCH_CONSTRAINTS_QUERY_FORMAT);
    for p in chunk {
        cmd.arg(p);
    }
    let output = match crate::engine::command::run_command_capped_output_with_cancel_and_timeout(
        cmd,
        "spawn rpm -qp ARCH+CONSTRAINTS batch",
        cancel_token,
        RPM_QUERY_TIMEOUT,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            return flatten_chunk_error(e, chunk.len(), "rpm -qp ARCH+CONSTRAINTS batch");
        }
    };
    if output.status.success() {
        let raw = String::from_utf8_lossy(&output.stdout);
        // 三行/SRPM：ARCH、EXCL=、EXCLD=。行数对账（3×chunk）守住解析器漏吐。
        let lines: Vec<&str> = raw.lines().collect();
        if lines.len() == chunk.len() * 3 {
            return chunk
                .iter()
                .enumerate()
                .map(|(i, _)| {
                    let arch = lines[i * 3].trim().to_string();
                    let (_, constraints) = parse_br_arch_constraints_lines(
                        lines[i * 3 + 1..i * 3 + 3].iter().map(|l| l.to_string()),
                    );
                    Ok((arch, constraints))
                })
                .collect();
        }
    }
    // 批量失败或行数不匹配：退回单包查询，确保错误信息精确到文件。
    let mut results = Vec::with_capacity(chunk.len());
    for p in chunk {
        results.push(parse_arch_and_constraints_from_srpm(p, cancel_token).await);
    }
    results
}

/// 批量从 SRPM header 读取 ARCH：按 `RPM_QP_BATCH_SIZE` 分批各调一次 `rpm -qp`，
/// 批失败退回单包查询，返回顺序与输入一致；`cancel_token` + 60s 超时透传 capped
/// 执行器（chain 取消按进程组终止，单包 fallback 同限）。
pub async fn parse_arch_from_srpms(
    srpms: &[PathBuf],
    cancel_token: Option<&CancellationToken>,
) -> Vec<crate::Result<String>> {
    let mut results = Vec::with_capacity(srpms.len());
    if srpms.is_empty() {
        return results;
    }
    for chunk in srpms.chunks(RPM_QP_BATCH_SIZE) {
        results.extend(parse_arch_chunk(chunk, cancel_token).await);
    }
    results
}

/// 把批量 rpm -qp 执行器的 Err 拍平为整 chunk 结果向量：Cancelled 原样透传，
/// 其余（含 [`RPM_QUERY_TIMEOUT`] 的 Timeout）包成 DepsolveFailed——批量与单包
/// fallback 同限失败、错误形态一致；`context` 必须是批量命令语义（裸 Timeout
/// 呈现 "build timeout" 不可定位）。纯函数，便于测试超时映射。
fn flatten_chunk_error<T>(
    e: CrbsError,
    chunk_len: usize,
    context: &'static str,
) -> Vec<crate::Result<T>> {
    (0..chunk_len)
        .map(|_| {
            Err(match &e {
                CrbsError::Cancelled => CrbsError::Cancelled,
                other => CrbsError::DepsolveFailed {
                    message: format!("{context}: {other}"),
                },
            })
        })
        .collect()
}

async fn parse_arch_chunk(
    chunk: &[PathBuf],
    cancel_token: Option<&CancellationToken>,
) -> Vec<crate::Result<String>> {
    let mut cmd = tokio::process::Command::new("rpm");
    cmd.arg("-qp").arg("--queryformat").arg("%{ARCH}\n");
    for p in chunk {
        cmd.arg(p);
    }
    let output = match crate::engine::command::run_command_capped_output_with_cancel_and_timeout(
        cmd,
        "spawn rpm -qp ARCH batch",
        cancel_token,
        RPM_QUERY_TIMEOUT,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => return flatten_chunk_error(e, chunk.len(), "rpm -qp ARCH batch"),
    };
    if output.status.success() {
        let raw = String::from_utf8_lossy(&output.stdout);
        let lines = raw_lines(&raw);
        if lines.len() == chunk.len() {
            return lines.into_iter().map(|l| Ok(l.to_string())).collect();
        }
    }
    // 批量失败或输出行数不匹配：退回单包查询，确保错误信息精确到文件。
    let mut results = Vec::with_capacity(chunk.len());
    for p in chunk {
        results.push(parse_arch_from_srpm(p, cancel_token).await);
    }
    results
}

/// 单包 BR+ARCH+架构约束 queryformat：BR 块之后两行以 `EXCL=`/`EXCLD=` 字面
/// 前缀携带 `[%{EXCLUSIVEARCH} ]` / `[%{EXCLUDEARCH} ]` 数组迭代输出（`[]` 是
/// 迭代语法不落输出，行值为空格分隔裸值；缺失 = 空值；见 [`ArchConstraints`]）。
/// BR 行不可能撞前缀：行首 `EXCL=` 要求 requirename 恰为 `EXCL` 且 depflags
/// 渲染为空，包名字符集与 depflags 语义均排除该形态。
const SRPM_BR_ARCH_QUERY_FORMAT: &str = "%{ARCH}\n[%{REQUIRENAME} %{REQUIREFLAGS:depflags} %{REQUIREVERSION}\n]\nEXCL=[%{EXCLUSIVEARCH} ]\nEXCLD=[%{EXCLUDEARCH} ]";

/// 解析单包 queryformat 输出的 BR+ARCH+约束：首行 ARCH，其后 BR 行与
/// `EXCL=`/`EXCLD=` 约束行混排，按前缀切分（纯函数，可单测）。
fn parse_br_arch_constraints_lines(
    lines: impl Iterator<Item = String>,
) -> (Vec<String>, ArchConstraints) {
    let mut br = Vec::new();
    let mut constraints = ArchConstraints::default();
    for line in lines {
        if let Some(inner) = line.trim().strip_prefix("EXCL=") {
            constraints.exclusive = parse_constraint_field(inner);
        } else if let Some(inner) = line.trim().strip_prefix("EXCLD=") {
            constraints.exclude = parse_constraint_field(inner);
        } else if is_br_line(line.trim()) {
            br.push(line.trim().to_string());
        }
    }
    (br, constraints)
}

/// 解析单个架构约束字段值：数组迭代输出按空白分架构（缺失标签迭代 0 次 =
/// 空串 → 空集）；标量形态的 `(none)` 防御性归一为空集（防格式串被误改回
/// 标量形态或未来 rpm 行为差异）。
fn parse_constraint_field(raw: &str) -> Vec<String> {
    raw.split_whitespace()
        .filter(|t| *t != "(none)")
        .map(str::to_string)
        .collect()
}

/// 从 SRPM header 同时读 ARCH + BuildRequires + 架构约束：首行为 ARCH（scalar），
/// 后续为 BR（list）与 `EXCL=`/`EXCLD=` 约束行（见 [`SRPM_BR_ARCH_QUERY_FORMAT`]），
/// 过滤 `rpmlib(` 条目；`cancel_token` + 60s 超时兜底。
pub async fn parse_br_and_arch_from_srpm(
    srpm: &Path,
    cancel_token: Option<&CancellationToken>,
) -> crate::Result<SrpmBrArch> {
    let output = rpm_qp_single(
        srpm,
        SRPM_BR_ARCH_QUERY_FORMAT,
        "BR+ARCH",
        false,
        cancel_token,
    )
    .await?;

    let raw = String::from_utf8_lossy(&output.stdout);
    let mut lines = raw.lines().map(|l| l.to_string());
    let arch = lines
        .next()
        .map(|l| l.trim().to_string())
        .unwrap_or_default();
    let (br, constraints) = parse_br_arch_constraints_lines(lines);
    Ok(SrpmBrArch {
        arch,
        build_requires: br,
        arch_constraints: constraints,
    })
}

/// 批量从 SRPM header 同时读取 ARCH + BuildRequires + 架构约束（同
/// `parse_br_and_arch_from_srpm` 的结构体口径）：按 `RPM_QP_BATCH_SIZE`
/// 分批各调一次 `rpm -qp`，批失败退回单包查询，返回顺序与输入一致；
/// `cancel_token` + 60s 超时透传 capped 执行器（同 `parse_arch_from_srpms`）。
pub async fn parse_br_and_arch_from_srpms(
    srpms: &[PathBuf],
    cancel_token: Option<&CancellationToken>,
) -> Vec<crate::Result<SrpmBrArch>> {
    let mut results = Vec::with_capacity(srpms.len());
    if srpms.is_empty() {
        return results;
    }
    for chunk in srpms.chunks(RPM_QP_BATCH_SIZE) {
        results.extend(parse_br_and_arch_chunk(chunk, cancel_token).await);
    }
    results
}

async fn parse_br_and_arch_chunk(
    chunk: &[PathBuf],
    cancel_token: Option<&CancellationToken>,
) -> Vec<crate::Result<SrpmBrArch>> {
    let queryformat = format!(
        "%{{ARCH}}\n{}\n[%{{REQUIRENAME}} %{{REQUIREFLAGS:depflags}} %{{REQUIREVERSION}}\n]\
         \nEXCL=[%{{EXCLUSIVEARCH}} ]\nEXCLD=[%{{EXCLUDEARCH}} ]{}",
        BR_ARCH_BATCH_SEPARATOR, BR_BATCH_END_MARKER
    );
    let mut cmd = tokio::process::Command::new("rpm");
    cmd.arg("-qp").arg("--queryformat").arg(queryformat);
    for p in chunk {
        cmd.arg(p);
    }
    let output = match crate::engine::command::run_command_capped_output_with_cancel_and_timeout(
        cmd,
        "spawn rpm -qp BR+ARCH batch",
        cancel_token,
        RPM_QUERY_TIMEOUT,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => return flatten_chunk_error(e, chunk.len(), "rpm -qp BR+ARCH batch"),
    };
    if output.status.success() {
        let raw = String::from_utf8_lossy(&output.stdout);
        let parsed = parse_br_and_arch_batch_output(&raw);
        if parsed.len() == chunk.len() {
            return parsed.into_iter().map(Ok).collect();
        }
    }
    // 批量失败或解析块数不匹配：退回单包查询。
    let mut results = Vec::with_capacity(chunk.len());
    for p in chunk {
        results.push(parse_br_and_arch_from_srpm(p, cancel_token).await);
    }
    results
}

fn parse_br_and_arch_batch_output(raw: &str) -> Vec<SrpmBrArch> {
    let mut blocks: Vec<&str> = raw.split(BR_BATCH_END_MARKER).collect();
    if blocks.last().map(|s| s.trim().is_empty()).unwrap_or(false) {
        blocks.pop();
    }
    blocks
        .into_iter()
        .map(|block| {
            // 块内行不做预过滤：`%{ARCH}` 为空时首行是空行，先 filter(!empty) 会
            // 让 arch 误取分隔符、首条 BR 被"跳分隔行"吞掉（块数不变，对账检不出）。
            let mut lines = block.lines();
            let arch = lines
                .next()
                .map(|l| l.trim().to_string())
                .unwrap_or_default();
            // 第二行是批量分隔标记，仅当确实等于分隔符时跳过，避免误吞 BR。
            let second = lines.next();
            let rest: Box<dyn Iterator<Item = &str>> =
                if second.map(|l| l.trim()) == Some(BR_ARCH_BATCH_SEPARATOR) {
                    Box::new(lines)
                } else {
                    Box::new(second.into_iter().chain(lines))
                };
            let (br, constraints) = parse_br_arch_constraints_lines(rest.map(|l| l.to_string()));
            SrpmBrArch {
                arch,
                build_requires: br,
                arch_constraints: constraints,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::engine::depsolve::capability::CAPABILITY_INDEX_REPOQUERY_TIMEOUT;
    use crate::test_support::SrpmFixture;

    /// 输出解析：正常 `host\t<epoch>`、host/time 缺失 → None、time=0 照收（不降级不拒绝）。
    #[test]
    fn parse_srpm_replay_params_normal_and_missing_tags() {
        let (host, time) = parse_srpm_replay_params("probehost\t1700000000").unwrap();
        assert_eq!(host.as_deref(), Some("probehost"));
        assert_eq!(time, Some(1_700_000_000));

        let (host, time) = parse_srpm_replay_params("(none)\t1700000000").unwrap();
        assert_eq!(host, None);
        assert_eq!(time, Some(1_700_000_000));

        let (host, time) = parse_srpm_replay_params("probehost\t(none)").unwrap();
        assert_eq!(host.as_deref(), Some("probehost"));
        assert_eq!(time, None);

        let (host, time) = parse_srpm_replay_params("(none)\t(none)").unwrap();
        assert_eq!(host, None);
        assert_eq!(time, None);
        let (_, time) = parse_srpm_replay_params("h\t0").unwrap();
        assert_eq!(time, Some(0));
    }

    /// 硬错误钉：BUILDTIME 非整数（损坏头）→ NonIntegerBuildTime（坏输入
    /// 不降级）；空 time 字段 = 标签缺失，不是错误。
    #[test]
    fn parse_srpm_replay_params_rejects_corrupt_buildtime() {
        assert_eq!(
            parse_srpm_replay_params("host\tnot-a-number"),
            Err(ProbeOutputError::NonIntegerBuildTime(
                "not-a-number".to_string()
            ))
        );
        assert!(
            parse_srpm_replay_params("host\t").is_ok(),
            "empty time field = missing tag"
        );
        let (host, _) = parse_srpm_replay_params("we ird host\t42").unwrap();
        assert_eq!(host.as_deref(), Some("we ird host"));
    }

    /// 整行空输出硬错误钉：rpm 对坏 queryformat 仍退出 0、stdout 为空——
    /// 必须拒绝而非降级成 (None, None) 静默空转（标签缺失是字段级 `(none)`）。
    #[test]
    fn parse_srpm_replay_params_rejects_empty_output() {
        assert_eq!(parse_srpm_replay_params(""), Err(ProbeOutputError::Empty));
        assert_eq!(
            parse_srpm_replay_params("   \n\t "),
            Err(ProbeOutputError::Empty)
        );
    }

    /// 格式串钉：标签必须带花括号——缺花括号 `%TAG` 被 rpm 拒却仍退出 0
    ///（空输出），防格式串漂移。
    #[test]
    fn probe_queryformat_pins_braced_tags() {
        assert_eq!(SRPM_REPLAY_QUERY_FORMAT, "%{BUILDHOST}\t%{BUILDTIME}\n");
        assert!(SRPM_REPLAY_QUERY_FORMAT.contains("%{BUILDHOST}"));
        assert!(SRPM_REPLAY_QUERY_FORMAT.contains("%{BUILDTIME}"));
    }

    /// 超时映射回归：Timeout 拍平为整 chunk DepsolveFailed（与单包路径
    /// 错误形态一致），不落 Cancelled；消息必须携带命令上下文前缀。
    #[test]
    fn flatten_chunk_error_maps_timeout_to_depsolve_failed() {
        assert_eq!(RPM_QUERY_TIMEOUT, std::time::Duration::from_secs(60));
        // capability 索引 repoquery 预算钉：600s，回落 60s 档会误杀慢链路上的大仓集索引。
        assert_eq!(
            CAPABILITY_INDEX_REPOQUERY_TIMEOUT,
            std::time::Duration::from_secs(600)
        );
        let results: Vec<crate::Result<String>> =
            flatten_chunk_error(CrbsError::Timeout, 3, "rpm -qp ARCH batch");
        assert_eq!(results.len(), 3);
        for r in results {
            match r {
                Err(CrbsError::DepsolveFailed { message }) => {
                    assert!(
                        message.starts_with("rpm -qp ARCH batch: "),
                        "flattened error must carry the command context: {message}"
                    );
                }
                other => panic!("timeout must flatten to DepsolveFailed, got: {other:?}"),
            }
        }
    }

    /// 取消透传回归：Cancelled 不被包装成 DepsolveFailed。
    #[test]
    fn flatten_chunk_error_passes_cancelled_through() {
        let results: Vec<crate::Result<String>> =
            flatten_chunk_error(CrbsError::Cancelled, 2, "rpm -qp BR+ARCH batch");
        assert_eq!(results.len(), 2);
        for r in results {
            assert!(
                matches!(r, Err(CrbsError::Cancelled)),
                "Cancelled must pass through unwrapped, got: {:?}",
                r
            );
        }
    }

    // 需调用 `rpm` 解析真实 SRPM，仅 Linux 有意义（macOS homebrew rpm 对
    // Linux 格式 SRPM 兼容性不保证）。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn parse_build_requires_from_srpm_reads_real_glibc() {
        // 构造含 BR（含版本约束）的最小 SRPM，验证 header 读取与 rpmlib 过滤。
        let tmp = tempfile::tempdir().unwrap();
        let srpm = build_test_srpm(&tmp, None);

        let br = parse_build_requires_from_srpm(&srpm)
            .await
            .expect("parse_build_requires_from_srpm failed");

        assert!(
            br.iter().any(|b| b.starts_with("gcc")),
            "missing gcc: {:?}",
            br
        );
        assert!(br.iter().any(|b| b == "make"), "missing make: {:?}", br);
        assert!(br.iter().any(|b| b == "bash"), "missing bash: {:?}", br);

        assert!(
            br.iter().any(|b| b.contains("gcc") && b.contains("7.0")),
            "version constraint lost: {:?}",
            br
        );

        assert!(
            br.iter().all(|b| !b.starts_with("rpmlib(")),
            "rpmlib entries leaked: {:?}",
            br
        );
    }

    // 辅助：最小 hello SRPM 夹具（BR 固定 gcc/make/bash，与历史夹具同形）；
    // 构造本体在共享 [`crate::test_support::build_srpm`]。
    #[cfg(target_os = "linux")]
    fn build_test_srpm(tmp: &tempfile::TempDir, buildarch: Option<&str>) -> PathBuf {
        crate::test_support::build_srpm(SrpmFixture {
            topdir: tmp.path(),
            name: "hello",
            version: "1.0",
            release: "1",
            buildarch,
            build_requires: &["gcc >= 7.0", "make", "bash"],
            exclusive: &[],
            exclude: &[],
        })
    }

    // 该测试需要调用 `rpm` 命令解析真实 SRPM，仅在 Linux 上有意义。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn parse_arch_from_srpm_detects_noarch() {
        let tmp = tempfile::tempdir().unwrap();
        let srpm = build_test_srpm(&tmp, Some("noarch"));
        let arch = parse_arch_from_srpm(&srpm, None)
            .await
            .expect("parse_arch_from_srpm failed");
        assert_eq!(arch, "noarch");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn parse_arch_from_srpm_detects_host_arch_for_arch_package() {
        let tmp = tempfile::tempdir().unwrap();
        let srpm = build_test_srpm(&tmp, None);
        let arch = parse_arch_from_srpm(&srpm, None)
            .await
            .expect("parse_arch_from_srpm failed");
        assert_eq!(arch, std::env::consts::ARCH);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn parse_br_and_arch_from_srpm_returns_arch_and_br() {
        let tmp = tempfile::tempdir().unwrap();
        let srpm = build_test_srpm(&tmp, Some("noarch"));
        let meta = parse_br_and_arch_from_srpm(&srpm, None)
            .await
            .expect("parse_br_and_arch_from_srpm failed");
        assert_eq!(meta.arch, "noarch");
        assert!(
            meta.arch_constraints.exclusive.is_empty() && meta.arch_constraints.exclude.is_empty(),
            "plain spec must carry no arch constraints: {:?}",
            meta.arch_constraints
        );
        assert!(
            meta.build_requires.iter().any(|b| b.starts_with("gcc")),
            "missing gcc: {:?}",
            meta.build_requires
        );
        assert!(
            meta.build_requires.iter().any(|b| b == "make"),
            "missing make: {:?}",
            meta.build_requires
        );
        assert!(
            meta.build_requires.iter().any(|b| b == "bash"),
            "missing bash: {:?}",
            meta.build_requires
        );
        assert!(
            meta.build_requires
                .iter()
                .all(|b| !b.starts_with("rpmlib(")),
            "rpmlib leaked: {:?}",
            meta.build_requires
        );
    }

    /// 真实约束 SRPM 回读：spec ExclusiveArch/ExcludeArch 行经 rpmbuild 打进
    /// header 数组标签，约束探测入口逐项解出（集合逐项相等）；无 BuildArch 时
    /// header ARCH = 宿主架构。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn parse_arch_and_constraints_from_srpm_reads_constraint_lines() {
        if !crate::test_support::rpm_spawnable() || !crate::test_support::rpmbuild_spawnable() {
            eprintln!("skipping: rpm/rpmbuild not available");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let srpm = crate::test_support::build_srpm(SrpmFixture {
            topdir: tmp.path(),
            name: "hello",
            version: "1.0",
            release: "1",
            buildarch: None,
            build_requires: &["gcc >= 7.0", "make", "bash"],
            exclusive: &["x86_64"],
            exclude: &["ppc64le"],
        });

        let (arch, constraints) = parse_arch_and_constraints_from_srpm(&srpm, None)
            .await
            .expect("parse_arch_and_constraints_from_srpm failed");

        assert_eq!(arch, std::env::consts::ARCH);
        assert_eq!(constraints.exclusive, vec!["x86_64".to_string()]);
        assert_eq!(constraints.exclude, vec!["ppc64le".to_string()]);
    }

    /// 批量 BR+ARCH 解析：正常块、空 ARCH 块的分隔符/BR 归位、约束行切分
    /// （EXCL=/EXCLD= 前缀不混入 BR）。
    #[test]
    fn test_parse_br_and_arch_batch_output() {
        let sep = BR_ARCH_BATCH_SEPARATOR;
        let end = BR_BATCH_END_MARKER;
        // 两个 SRPM：第一个 %{ARCH} 渲染为空（块首行是空行），第二个正常。
        // 行形态 = rpm 真实输出（迭代语法方括号不落输出）。
        let raw = format!(
            "\n{sep}\ngcc >= 8.0\nmake\nrpmlib(PayloadIsZstd) <= 5.2\n\
             EXCL=x86_64 aarch64 \nEXCLD=\n{end}\
             x86_64\n{sep}\npython3 >= 3.9\nEXCL=\nEXCLD=x86_64 \n{end}"
        );
        let out = parse_br_and_arch_batch_output(&raw);
        assert_eq!(out.len(), 2, "block count: {:?}", out);
        // 空 ARCH 块：arch 为空串（与单包路径一致），分隔符不被当 arch，
        // 且首条 BR 不被"跳分隔行"吞掉。
        assert_eq!(out[0].arch, "");
        assert_eq!(out[0].build_requires, vec!["gcc >= 8.0", "make"]);
        assert!(!out[0].build_requires.contains(&sep.to_string()));
        assert_eq!(out[0].arch_constraints.exclusive, vec!["x86_64", "aarch64"]);
        assert!(out[0].arch_constraints.exclude.is_empty());
        assert_eq!(out[1].arch, "x86_64");
        assert_eq!(out[1].build_requires, vec!["python3 >= 3.9"]);
        assert_eq!(out[1].arch_constraints.exclusive, Vec::<String>::new());
        assert_eq!(out[1].arch_constraints.exclude, vec!["x86_64"]);
    }

    /// 约束字段解析实测口径（rpm 6.0.2）：数组迭代缺失 = 空值 → 空集；
    /// 标量形态的 `(none)` 防御性归一为空集；空格分隔多架构。
    #[test]
    fn parse_constraint_field_normalizes_none_and_missing() {
        assert_eq!(
            parse_constraint_field("x86_64 aarch64 "),
            vec!["x86_64", "aarch64"]
        );
        assert_eq!(parse_constraint_field(""), Vec::<String>::new());
        assert_eq!(parse_constraint_field("(none)"), Vec::<String>::new());
        assert_eq!(parse_constraint_field(" (none) x86_64 "), vec!["x86_64"]);
    }

    /// 单包行切分：约束行走 ArchConstraints，不污染 BR；无约束包两字段空集
    /// （hello-no 型夹具：两标签全缺）。行形态 = rpm 真实输出（无方括号）。
    #[test]
    fn parse_br_arch_constraints_lines_splits_br_and_constraints() {
        let lines = vec![
            "gcc >= 8.0".to_string(),
            "EXCL=x86_64 ".to_string(),
            "EXCLD=".to_string(),
            "make".to_string(),
        ];
        let (br, c) = parse_br_arch_constraints_lines(lines.into_iter());
        assert_eq!(br, vec!["gcc >= 8.0", "make"]);
        assert_eq!(c.exclusive, vec!["x86_64"]);
        assert!(c.exclude.is_empty());

        let (br, c) = parse_br_arch_constraints_lines(
            vec![
                "bash".to_string(),
                "EXCL=".to_string(),
                "EXCLD=".to_string(),
            ]
            .into_iter(),
        );
        assert_eq!(br, vec!["bash"]);
        assert!(c.exclusive.is_empty() && c.exclude.is_empty());
    }

    /// 格式串钉：BR+ARCH queryformat 必须带新标签的花括号数组迭代形态（防
    /// 格式串漂移回标量形态——标量形态多架构只吐首个值；`[]` 是迭代语法、
    /// 不落输出，但缺失标签的迭代空转正是"缺失 = 空值"解析契约的前提）。
    #[test]
    fn probe_queryformat_pins_braced_arch_constraint_tags() {
        assert!(SRPM_BR_ARCH_QUERY_FORMAT.contains("[%{EXCLUSIVEARCH} ]"));
        assert!(SRPM_BR_ARCH_QUERY_FORMAT.contains("[%{EXCLUDEARCH} ]"));
        assert!(SRPM_BR_ARCH_QUERY_FORMAT.contains("EXCL=["));
        assert!(SRPM_BR_ARCH_QUERY_FORMAT.contains("EXCLD=["));
    }

    /// 具体架构兼容性矩阵：ExclusiveArch 非空且不含目标 →
    /// "not in"；ExcludeArch 含目标 → "excluded"；两者皆无/命中 → 兼容。
    /// 两约束并存时 ExclusiveArch 先裁决（与 crbs-server plan_srpm_arches 同序）。
    #[test]
    fn arch_constraints_concrete_matrix() {
        let both = ArchConstraints {
            exclusive: vec!["aarch64".to_string()],
            exclude: vec!["x86_64".to_string()],
        };
        let exc_only = ArchConstraints {
            exclusive: vec!["aarch64".to_string()],
            exclude: vec![],
        };
        let excl_only = ArchConstraints {
            exclusive: vec![],
            exclude: vec!["x86_64".to_string()],
        };
        let none = ArchConstraints::default();

        // ExclusiveArch 先裁决：x86_64 同时被 exclude，但"not in"先命中。
        let r = both.concrete_incompatible("x86_64").unwrap();
        assert!(r.contains("not in ExclusiveArch [aarch64]"), "got: {r}");
        assert!(both.concrete_incompatible("aarch64").is_none());
        assert!(exc_only.concrete_incompatible("x86_64").is_some());
        assert!(exc_only.concrete_incompatible("aarch64").is_none());
        assert!(excl_only
            .concrete_incompatible("x86_64")
            .unwrap()
            .contains("excluded by ExcludeArch [x86_64]"));
        assert!(excl_only.concrete_incompatible("aarch64").is_none());
        assert!(none.concrete_incompatible("x86_64").is_none());
    }

    /// noarch 宿主代理矩阵（rpm 6.0.2 实测）：ExclusiveArch 对
    /// noarch target 豁免（矛盾 spec 自然落入本分支，不错杀）；ExcludeArch
    /// 含宿主 → 不兼容并点名宿主代理语义。
    #[test]
    fn arch_constraints_noarch_host_matrix() {
        let contradict = ArchConstraints {
            exclusive: vec!["x86_64".to_string()],
            exclude: vec![],
        };
        // BuildArch: noarch + ExclusiveArch: x86_64 —— rpm 对 noarch target 放行。
        assert!(contradict.noarch_host_incompatible("x86_64").is_none());
        assert!(contradict.noarch_host_incompatible("aarch64").is_none());

        let excl = ArchConstraints {
            exclusive: vec![],
            exclude: vec!["x86_64".to_string()],
        };
        let r = excl.noarch_host_incompatible("x86_64").unwrap();
        assert!(
            r.contains("excluded by ExcludeArch [x86_64] (noarch build host)"),
            "got: {r}"
        );
        assert!(excl.noarch_host_incompatible("aarch64").is_none());
        assert!(ArchConstraints::default()
            .noarch_host_incompatible("x86_64")
            .is_none());
    }

    /// 精确匹配矩阵（实测口径见 [`ArchConstraints::concrete_incompatible`]）：
    /// 约束与 target 逐字比对，微架构变体与基础架构互不归属——
    /// `ExclusiveArch: x86_64` 拒 `x86_64_v3`，`ExclusiveArch: x86_64_v3` 拒
    /// `x86_64`，`ExcludeArch: x86_64` 不排 `x86_64_v3`。
    #[test]
    fn concrete_incompatible_matches_literal_arch_only() {
        let exc = ArchConstraints {
            exclusive: vec!["x86_64".to_string()],
            exclude: vec![],
        };
        assert!(exc
            .concrete_incompatible("x86_64_v3")
            .unwrap()
            .contains("not in ExclusiveArch [x86_64]"));
        assert!(exc.concrete_incompatible("x86_64").is_none());
        assert!(exc
            .concrete_incompatible("aarch64")
            .unwrap()
            .contains("not in ExclusiveArch"));

        // 约束侧写微变体（罕见形态）同样逐字比对：x86_64 不在其列。
        let exc_v = ArchConstraints {
            exclusive: vec!["x86_64_v3".to_string()],
            exclude: vec![],
        };
        assert!(exc_v
            .concrete_incompatible("x86_64")
            .unwrap()
            .contains("not in ExclusiveArch"));
        assert!(exc_v.concrete_incompatible("x86_64_v3").is_none());

        // ExcludeArch 精确匹配：x86_64 不排除 x86_64_v3（rpm 4.18.2 实测放行）。
        let excd = ArchConstraints {
            exclusive: vec![],
            exclude: vec!["x86_64".to_string()],
        };
        assert!(excd.concrete_incompatible("x86_64_v3").is_none());
        assert!(excd
            .concrete_incompatible("x86_64")
            .unwrap()
            .contains("excluded by ExcludeArch [x86_64]"));
    }

    /// 分派矩阵：srpm_arch = "noarch" 走宿主代理检查（ExclusiveArch 豁免、
    /// 文案带 noarch build host 后缀），其余 srpm_arch 走具体架构检查。
    #[test]
    fn incompatible_for_dispatches_by_srpm_arch() {
        let excl = ArchConstraints {
            exclusive: vec![],
            exclude: vec!["x86_64".to_string()],
        };
        let r = excl.incompatible_for("noarch", "x86_64").unwrap();
        assert!(r.contains("(noarch build host)"), "got: {r}");
        let r = excl.incompatible_for("x86_64", "x86_64").unwrap();
        assert!(
            r.contains("excluded by ExcludeArch") && !r.contains("noarch build host"),
            "got: {r}"
        );

        // ExclusiveArch 形态：noarch 豁免，具体架构照常裁决。
        let exc = ArchConstraints {
            exclusive: vec!["aarch64".to_string()],
            exclude: vec![],
        };
        assert!(exc.incompatible_for("noarch", "x86_64").is_none());
        assert!(exc.incompatible_for("riscv64", "riscv64").is_some());
    }

    // Cancelled 透传回归构造：预触发 token 让执行器 select 立即返回 Cancelled
    //（rpm 只需能 spawn）；rpm 缺失的环境跳过——CI runner 为 Ubuntu，必跑。

    async fn assert_cancelled_propagates(err: crate::Result<impl Sized>) {
        let err = match err {
            Ok(_) => panic!("pre-cancelled token must fail fast, got Ok"),
            Err(e) => e,
        };
        assert!(
            matches!(err, CrbsError::Cancelled),
            "Cancelled must propagate, got: {:?}",
            err
        );
    }

    #[tokio::test]
    async fn parse_arch_from_srpm_propagates_cancelled() {
        if !crate::test_support::rpm_spawnable() {
            eprintln!("skipping: rpm not available");
            return;
        }
        let token = CancellationToken::new();
        token.cancel();
        assert_cancelled_propagates(
            parse_arch_from_srpm(Path::new("/nonexistent/hello-1.0-1.src.rpm"), Some(&token)).await,
        )
        .await;
    }

    #[tokio::test]
    async fn parse_br_and_arch_from_srpm_propagates_cancelled() {
        if !crate::test_support::rpm_spawnable() {
            eprintln!("skipping: rpm not available");
            return;
        }
        let token = CancellationToken::new();
        token.cancel();
        assert_cancelled_propagates(
            parse_br_and_arch_from_srpm(
                Path::new("/nonexistent/hello-1.0-1.src.rpm"),
                Some(&token),
            )
            .await,
        )
        .await;
    }
}

/// 校验从 SRPM header 解析出的 N-V-R：非空、含 `-`（N-V-R 最小形态）、
/// 不含路径分隔符与以 `.` 开头的分量（pkg_name 直接拼结果目录路径，会落
/// CurDir/ParentDir 或隐藏目录，边界拒绝同 [`crate::engine::srpm_pkg_name`]）。
/// 纯函数，便于测试。
fn validate_nevr(nevr: &str) -> crate::Result<String> {
    let nevr = nevr.trim();
    if nevr.is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: "SRPM header produced empty N-V-R (corrupt RPM?)".into(),
        });
    }
    if nevr.chars().any(|c| c.is_control()) {
        return Err(CrbsError::ValidationFailed {
            message: format!("SRPM N-V-R {nevr:?} contains control characters"),
        });
    }
    if nevr.len() > 128 {
        return Err(CrbsError::ValidationFailed {
            message: format!("SRPM N-V-R too long (max 128, got {})", nevr.len()),
        });
    }
    if nevr.contains('/') || nevr.starts_with('.') || nevr.split('-').next() == Some("") {
        return Err(CrbsError::ValidationFailed {
            message: format!("SRPM N-V-R {nevr:?} is not filesystem-safe"),
        });
    }
    if !nevr.contains('-') {
        return Err(CrbsError::ValidationFailed {
            message: format!("SRPM N-V-R {nevr:?} lacks '-' (not N-V-R)"),
        });
    }
    Ok(nevr.to_string())
}

/// 批量从 SRPM header 读取 `Name-Version-Release`（任务显示名与结果目录的
/// 真值来源，与上传文件名解耦）：同 [`parse_arch_from_srpms`] 的分批/超时/
/// 取消口径；单项解析失败原样返回 Err，由调用方决定拒绝语义（提交入口
/// fail-fast 400）。
pub async fn parse_nevr_from_srpms(
    srpms: &[PathBuf],
    cancel_token: Option<&CancellationToken>,
) -> Vec<crate::Result<String>> {
    let mut results = Vec::with_capacity(srpms.len());
    if srpms.is_empty() {
        return results;
    }
    for chunk in srpms.chunks(RPM_QP_BATCH_SIZE) {
        let mut cmd = tokio::process::Command::new("rpm");
        cmd.arg("-qp")
            .arg("--queryformat")
            .arg("%{NAME}-%{VERSION}-%{RELEASE}\n");
        for p in chunk {
            cmd.arg(p);
        }
        let output =
            match crate::engine::command::run_command_capped_output_with_cancel_and_timeout(
                cmd,
                "spawn rpm -qp NEVR batch",
                cancel_token,
                RPM_QUERY_TIMEOUT,
            )
            .await
            {
                Ok(o) => o,
                Err(e) => {
                    results.extend(flatten_chunk_error(e, chunk.len(), "rpm -qp NEVR batch"));
                    continue;
                }
            };
        if output.status.success() {
            let raw = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = raw_lines(&raw);
            if lines.len() == chunk.len() {
                results.extend(lines.into_iter().map(validate_nevr));
                continue;
            }
        }
        // 批量失败或行数不匹配：退回单包查询，确保错误信息精确到文件。
        for p in chunk {
            results.push(parse_nevr_from_srpm(p, cancel_token).await);
        }
    }
    results
}

/// 按行切分命令 stdout（过滤纯空行）。
fn raw_lines(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect()
}

/// BR 行过滤器：跳过空行与 `rpmlib(` 虚拟能力（宿主运行时自给，非构建依赖）。
fn is_br_line(line: &str) -> bool {
    !line.is_empty() && !line.starts_with("rpmlib(")
}

#[cfg(test)]
mod nevr_tests {
    use super::validate_nevr;

    #[test]
    fn nevr_accepts_canonical() {
        assert_eq!(validate_nevr("vim-9.0.2092-45").unwrap(), "vim-9.0.2092-45");
    }

    #[test]
    fn nevr_accepts_tilde_and_caret() {
        assert!(validate_nevr("kernel-6.6.0-0.rc1~1").is_ok());
    }

    #[test]
    fn nevr_rejects_empty_and_dashless() {
        assert!(validate_nevr("").is_err());
        assert!(validate_nevr("noversion").is_err());
    }

    #[test]
    fn nevr_rejects_path_traversal_shapes() {
        assert!(validate_nevr("../evil-1-1").is_err());
        assert!(validate_nevr("a/b-1-1").is_err());
        assert!(validate_nevr(".hidden-1-1").is_err());
    }
}

/// 单包 N-V-R 查询（批量失败时的单包回退路径，错误信息精确到文件）。
async fn parse_nevr_from_srpm(
    srpm: &Path,
    cancel_token: Option<&CancellationToken>,
) -> crate::Result<String> {
    let mut cmd = tokio::process::Command::new("rpm");
    cmd.arg("-qp")
        .arg("--queryformat")
        .arg("%{NAME}-%{VERSION}-%{RELEASE}")
        .arg(srpm);
    let output = crate::engine::command::run_command_capped_output_with_cancel_and_timeout(
        cmd,
        "spawn rpm -qp NEVR",
        cancel_token,
        RPM_QUERY_TIMEOUT,
    )
    .await
    .map_err(|e| match e {
        CrbsError::Cancelled => CrbsError::Cancelled,
        other => CrbsError::DepsolveFailed {
            message: format!("rpm -qp NEVR for {}: {}", srpm.display(), other),
        },
    })?;
    if !output.status.success() {
        return Err(CrbsError::DepsolveFailed {
            message: format!(
                "rpm -qp NEVR for {}: exit {}",
                srpm.display(),
                output.status
            ),
        });
    }
    validate_nevr(String::from_utf8_lossy(&output.stdout).trim())
}

#[cfg(test)]
mod nevr_fallback_tests {
    use super::validate_nevr;

    #[test]
    fn nevr_rejects_control_characters() {
        assert!(validate_nevr("vim-9.0\n-45").is_err());
        assert!(validate_nevr("vim-9.0\r-45").is_err());
        assert!(validate_nevr("vim-9.0\0-45").is_err());
    }

    #[test]
    fn nevr_rejects_overlong() {
        let long = format!("p-{}", "1".repeat(200));
        assert!(validate_nevr(&long).is_err());
    }
}
