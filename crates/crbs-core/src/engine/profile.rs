// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建 Profiling：从 build.log 解析各 phase 耗时并写入 `result_dir/profile.json`。

use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::warn;

/// 单次构建的 profile 数据。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BuildProfile {
    /// 构建 id。
    pub build_id: i64,
    /// SRPM 文件名。
    pub srpm: String,
    /// 总耗时（秒）。
    pub total_seconds: f64,
    /// 是否命中 SharedLayer。
    pub shared_layer_hit: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// ccache 统计（启用 ccache 时存在）。
    pub ccache: Option<CcacheStats>,
    /// 各 phase 耗时。
    pub phases: Vec<BuildPhase>,
}

impl BuildProfile {
    /// 返回最慢的 phase 名称及其耗时（秒）。
    pub fn slowest_phase(&self) -> Option<(&str, f64)> {
        self.phases
            .iter()
            .filter(|p| !p.skipped.unwrap_or(false))
            .max_by(|a, b| {
                a.duration_seconds
                    .partial_cmp(&b.duration_seconds)
                    .unwrap_or(Ordering::Equal)
            })
            .map(|p| (p.name.as_str(), p.duration_seconds))
    }
}

/// ccache 统计摘要。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CcacheStats {
    /// ccache 是否启用。
    pub enabled: bool,
    /// 命中率（0.0-1.0）。
    pub hit_rate: f64,
    /// 可缓存的编译调用数。
    pub cacheable_calls: u64,
    /// 命中数。
    pub cache_hits: u64,
}

/// 单个 phase。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BuildPhase {
    /// phase 名称。
    pub name: String,
    /// 耗时（秒）。
    pub duration_seconds: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// 是否被跳过。
    pub skipped: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// 跳过原因（skipped 时存在）。
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// 退出码（非 0 退出时存在）。
    pub exit_code: Option<i32>,
}

/// 流式解析 build.log 文件：逐行消费不整体载入内存——日志无大小上限（内核级
/// 构建可达 GB），provenance 收尾在服务器进程内、并发构建成倍放大峰值。
pub async fn parse_profile_from_log_file(
    path: &Path,
    build_id: i64,
    srpm: &str,
    total_seconds: f64,
    shared_layer_hit: bool,
    ccache_enabled: bool,
) -> crate::Result<BuildProfile> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let f = tokio::fs::File::open(path)
        .await
        .map_err(|e| crate::error::CrbsError::from_io_context("open build.log for profiling", e))?;
    let mut reader = BufReader::new(f);
    let mut parser = ProfileLineParser::new(ccache_enabled);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await.map_err(|e| {
            crate::error::CrbsError::from_io_context("read build.log for profiling", e)
        })?;
        if n == 0 {
            break;
        }
        parser.feed_line(&line);
    }
    Ok(parser.finish(build_id, srpm, total_seconds, shared_layer_hit))
}

/// build phase 内的 rpmbuild 子阶段观测（时间线失败定位用）。来源是 rpmbuild
/// 打进 build.log 的阶段边界行（`Executing(%prep): ...`）与失败归属行
///（`error: Bad exit status from ... (%check)`）。
#[derive(Debug, Clone, PartialEq)]
pub struct SubPhase {
    /// 子阶段名，`"%prep"` 形态（含 % 前缀）。
    pub name: String,
    /// 命中 `error: Bad exit status from ... (%name)` 归属行。
    pub failed: bool,
    /// `Executing(%name)` 行在 build.log 中的行号（1 起）；日志页 `?line=` 跳转锚。
    pub line: u64,
    /// failed 时归属行原文（失败面板错误摘录）。
    pub error_line: Option<String>,
    /// 阶段开始时间戳（epoch 秒）：仅 `# CRBS_SUBPHASE` 插桩标记携带，Executing 行（降级路径）为 None。
    pub start: Option<f64>,
    /// 阶段耗时（秒）= 下一段 start − 本段 start；末段 = build END − start。
    /// 无插桩数据（降级路径 / build 未闭合）为 None。
    pub duration: Option<f64>,
}

/// Web UI 阶段时间线视角的单个 phase 区间：与 [`BuildPhase`]（profile.json 终态
/// 耗时视角）不同，保留 START 时间戳与标记出现序，START 后未见 END 判 running
///（实时流增量更新用）。
#[derive(Debug, Clone, PartialEq)]
pub struct PhaseSpan {
    /// phase 名称。
    pub name: String,
    /// START 时间戳（epoch 秒）；SKIP 标记无时间戳，为 0.0。
    pub start: f64,
    /// END 时间戳（epoch 秒）；构建进行中 / 中断时无 END，为 None。
    pub end: Option<f64>,
    /// END 标记携带的退出码；SKIP 与未闭合 START 为 None。
    pub exit_code: Option<i32>,
    /// SKIP 标记：该 phase 未执行。
    pub skipped: bool,
    /// SKIP 原因（shared_layer / ccache_disabled / skipped）。
    pub reason: Option<String>,
    /// START（或 SKIP）标记的日志行号（1 起，`?line=` 跳转锚），重复 START 刷新
    /// 起点时同步刷新。行号相对解析输入文本——日志页截断 tail 时与全文件行号
    /// 错位（超界 no-op 兜底；详情页走 `phase_timeline_spans` 全文件扫描，行号真实）。
    pub line: u64,
    /// build phase 内的 rpmbuild 子阶段（按 Executing 行出现序）；非 build phase 恒为空。
    pub sub: Vec<SubPhase>,
}

impl PhaseSpan {
    /// 时间线状态：SKIP → skipped；END exit!=0 → failed；无 END → running；否则 done。
    pub fn state(&self) -> &'static str {
        if self.skipped {
            "skipped"
        } else if let Some(exit) = self.exit_code {
            if exit == 0 {
                "done"
            } else {
                "failed"
            }
        } else {
            "running"
        }
    }

    /// 已流逝秒数：END 已知用 end-start；running 用 `now`-start；SKIP 恒 0。
    pub fn elapsed_seconds(&self, now: f64) -> f64 {
        if self.skipped {
            return 0.0;
        }
        (self.end.unwrap_or(now) - self.start).max(0.0)
    }
}

/// 解析 build.log 文本中的 `CRBS_PHASE_*` 标记为时间线区间（顺序 = 标记出现
/// 序）；行号 1 起枚举后交给 [`parse_phase_markers_numbered`]（子阶段行号锚）。
/// 与 `ProfileLineParser` 语义不同（终态耗时 vs START 序 + running 判定），不复用
/// 状态机。容忍乱序与标记双写：无 START 的 END 忽略（tail 截断丢头部 START
/// 同理，不误报）；同名重复 START 复用既有 span 刷新起点；重复 SKIP 只记一次。
pub fn parse_phase_markers(text: &str) -> Vec<PhaseSpan> {
    let numbered: Vec<(u64, &str)> = text
        .lines()
        .enumerate()
        .map(|(i, line)| (i as u64 + 1, line))
        .collect();
    parse_phase_markers_numbered(&numbered)
}

/// 带行号版解析（服务端流式扫描与内存入口共用）：除 `CRBS_PHASE_*` 标记外，
/// 还在 build span 打开期间观测 rpmbuild 自带的子阶段边界行——
/// `Executing(%xxx): ...` 记入 [`PhaseSpan::sub`]（行号 = 日志行号，供日志页
/// `?line=` 定位）；`error: Bad exit status from ... (%xxx)` 标 failed 并存归属行
/// 原文。Executing 行只在 build START 未闭合期间匹配（其它阶段同名噪声不误收）。
pub fn parse_phase_markers_numbered(lines: &[(u64, &str)]) -> Vec<PhaseSpan> {
    let mut spans: Vec<PhaseSpan> = Vec::new();
    let mut open: HashMap<String, usize> = HashMap::new();

    for &(line_no, line) in lines {
        let trimmed = line.trim();
        // 标记以 '# CRBS_PHASE_...' 形式写入（pipeline compose echo 输出）。
        let payload = trimmed.strip_prefix('#').map(str::trim).unwrap_or(trimmed);

        if let Some(rest) = payload.strip_prefix("CRBS_PHASE_START ") {
            let mut parts = rest.split_whitespace();
            if let (Some(name), Some(ts)) = (
                parts.next(),
                parts.next().and_then(|s| s.parse::<f64>().ok()),
            ) {
                if let Some(&i) = open.get(name) {
                    spans[i].start = ts;
                    spans[i].end = None;
                    spans[i].exit_code = None;
                    // noarch 重试会重跑整个 phase：旧 attempt 子阶段观测与行号锚一并作废。
                    spans[i].sub = Vec::new();
                    spans[i].line = line_no;
                } else {
                    open.insert(name.to_string(), spans.len());
                    spans.push(PhaseSpan {
                        name: name.to_string(),
                        start: ts,
                        end: None,
                        exit_code: None,
                        skipped: false,
                        reason: None,
                        line: line_no,
                        sub: Vec::new(),
                    });
                }
            }
        } else if let Some(rest) = payload.strip_prefix("CRBS_PHASE_END ") {
            let mut parts = rest.split_whitespace();
            let name = parts.next();
            let exit = parts.next().and_then(|s| s.parse::<i32>().ok());
            let ts = parts.next().and_then(|s| s.parse::<f64>().ok());
            if let (Some(name), Some(end_ts)) = (name, ts) {
                if let Some(i) = open.remove(name) {
                    spans[i].end = Some(end_ts);
                    spans[i].exit_code = exit;
                    // 末段时长收尾：build END 即最后一个插桩子阶段的结束。
                    if name == "build" {
                        if let Some(last) = spans[i].sub.last_mut() {
                            if let Some(start) = last.start {
                                if last.duration.is_none() {
                                    last.duration = Some((end_ts - start).max(0.0));
                                }
                            }
                        }
                    }
                }
            }
        } else if let Some(rest) = payload.strip_prefix("CRBS_PHASE_SKIP ") {
            let mut parts = rest.split_whitespace();
            if let Some(name) = parts.next() {
                let reason = parts.collect::<Vec<_>>().join(" ");
                let seen = spans.iter().any(|s| s.name == name);
                if !seen {
                    spans.push(PhaseSpan {
                        name: name.to_string(),
                        start: 0.0,
                        end: None,
                        exit_code: None,
                        skipped: true,
                        reason: if reason.is_empty() {
                            None
                        } else {
                            Some(reason)
                        },
                        line: line_no,
                        sub: Vec::new(),
                    });
                }
            }
        } else if open.contains_key("build") {
            // build span 打开期间：观测 rpmbuild 子阶段边界 / 失败归属行。插桩标记
            //（rpmbuild_bash 的 awk 过滤器回写）# CRBS_SUBPHASE %prep <ts> 携带时间戳，
            // 优先于 Executing 行（同名混合以插桩序列为准）。
            if let Some(rest) = payload.strip_prefix("CRBS_SUBPHASE ") {
                let mut parts = rest.split_whitespace();
                let (Some(name), Some(ts)) = (parts.next(), parts.next()) else {
                    // 形态异常的插桩行：跳过，解析继续。
                    continue;
                };
                let Ok(start) = ts.parse::<f64>() else {
                    continue;
                };
                let span = &mut spans[open["build"]];
                // 插桩序列出现即清掉 Executing 行的降级观测（两者不混用）。
                if span.sub.iter().any(|s| s.start.is_none()) {
                    span.sub.clear();
                }
                if let Some(prev) = span.sub.last_mut() {
                    if prev.duration.is_none() {
                        prev.duration = Some(start - prev.start.unwrap_or(start));
                    }
                }
                span.sub.push(SubPhase {
                    name: name.to_string(),
                    failed: false,
                    line: line_no,
                    error_line: None,
                    start: Some(start),
                    duration: None,
                });
            }
            // Executing(%prep): /bin/sh -e /var/tmp/rpm-tmp.XXX
            else if let Some(rest) = payload.strip_prefix("Executing(%") {
                if let Some(end) = rest.find("):") {
                    let name = &rest[..end];
                    // 插桩序列存在时 Executing 行是冗余降级观测，跳过。
                    let instrumented = spans[open["build"]].sub.iter().any(|s| s.start.is_some());
                    if !instrumented {
                        // 子阶段名只收小写与下划线（%generate_buildrequires 等），其它形态不收。
                        if !name.is_empty()
                            && name.chars().all(|c| c.is_ascii_lowercase() || c == '_')
                        {
                            spans[open["build"]].sub.push(SubPhase {
                                name: format!("%{name}"),
                                failed: false,
                                line: line_no,
                                error_line: None,
                                start: None,
                                duration: None,
                            });
                        }
                    }
                }
            }
            // error: Bad exit status from /var/tmp/rpm-tmp.XXX (%check)
            if let Some(rest) = payload.strip_prefix("error: Bad exit status from ") {
                if let Some(paren) = rest.find("(%") {
                    let name = rest[paren + 1..].trim_end_matches(')');
                    if let Some(sub) = spans[open["build"]]
                        .sub
                        .iter_mut()
                        .rev()
                        .find(|s| s.name == name)
                    {
                        sub.failed = true;
                        sub.error_line = Some(trimmed.to_string());
                    }
                }
            }
        }
    }
    spans
}

/// 行级解析状态机：`feed_line` 消费日志行，`finish` 产出 [`BuildProfile`]。
struct ProfileLineParser {
    phases: Vec<BuildPhase>,
    starts: HashMap<String, f64>,
    build_end_ts: Option<f64>,
    rpm_timestamps: Vec<(String, f64)>,
    /// 防御去重：标记双写产生重复 SKIP 行——START/END 天然幂等，SKIP 不幂等。
    last_skip: Option<String>,
    ccache: Option<CcacheLineCounter>,
}

/// ccache `-s` 输出的逐行计数器（正则在构造期编译一次）。
struct CcacheLineCounter {
    direct_re: regex::Regex,
    preproc_re: regex::Regex,
    miss_re: regex::Regex,
    direct: u64,
    preprocessed: u64,
    miss: u64,
    found: bool,
}

impl CcacheLineCounter {
    fn new() -> Option<Self> {
        // 正则硬编码：编译失败 = 代码 bug，warn 留痕后再降级 None。
        let compile = |pattern: &str| match regex::Regex::new(pattern) {
            Ok(re) => Some(re),
            Err(e) => {
                tracing::warn!(pattern, error = %e, "Failed to compile ccache regex");
                None
            }
        };
        Some(Self {
            direct_re: compile(r"cache hit \(direct\):?\s*(\d+)")?,
            preproc_re: compile(r"cache hit \(preprocessed\):?\s*(\d+)")?,
            miss_re: compile(r"cache miss(?:es)?:?\s*(\d+)")?,
            direct: 0,
            preprocessed: 0,
            miss: 0,
            found: false,
        })
    }

    fn feed_line(&mut self, line: &str) {
        if let Some(cap) = self.direct_re.captures(line) {
            if let Ok(n) = cap[1].parse::<u64>() {
                self.direct = n;
                self.found = true;
            }
        }
        if let Some(cap) = self.preproc_re.captures(line) {
            if let Ok(n) = cap[1].parse::<u64>() {
                self.preprocessed = n;
                self.found = true;
            }
        }
        if let Some(cap) = self.miss_re.captures(line) {
            if let Ok(n) = cap[1].parse::<u64>() {
                self.miss = n;
                self.found = true;
            }
        }
    }

    fn finish(&self) -> Option<CcacheStats> {
        if !self.found {
            return None;
        }
        let hits = self.direct + self.preprocessed;
        let calls = hits + self.miss;
        let hit_rate = if calls > 0 {
            hits as f64 / calls as f64
        } else {
            0.0
        };
        Some(CcacheStats {
            enabled: true,
            hit_rate,
            cacheable_calls: calls,
            cache_hits: hits,
        })
    }
}

impl ProfileLineParser {
    fn new(ccache_enabled: bool) -> Self {
        Self {
            phases: Vec::new(),
            starts: HashMap::new(),
            build_end_ts: None,
            rpm_timestamps: Vec::new(),
            last_skip: None,
            ccache: if ccache_enabled {
                CcacheLineCounter::new()
            } else {
                None
            },
        }
    }

    fn feed_line(&mut self, line: &str) {
        let trimmed = line.trim();
        // 支持可选的 '#' 前缀，因为 pipeline 注入的标记以 '# CRBS_PHASE_...' 形式输出
        let payload = trimmed
            .strip_prefix('#')
            .map(|s| s.trim())
            .unwrap_or(trimmed);

        if let Some(rest) = payload.strip_prefix("CRBS_PHASE_START ") {
            let mut parts = rest.split_whitespace();
            if let Some(name) = parts.next() {
                if let Some(ts_str) = parts.next() {
                    if let Ok(ts) = ts_str.parse::<f64>() {
                        self.starts.insert(name.to_string(), ts);
                    }
                }
            }
        } else if let Some(rest) = payload.strip_prefix("CRBS_PHASE_END ") {
            let mut parts = rest.split_whitespace();
            if let Some(name) = parts.next() {
                let exit_code = parts.next().and_then(|s| s.parse::<i32>().ok());
                if let Some(ts_str) = parts.next() {
                    if let Ok(end_ts) = ts_str.parse::<f64>() {
                        if name == "build" {
                            self.build_end_ts = Some(end_ts);
                        }
                        if let Some(&start_ts) = self.starts.get(name) {
                            self.phases.push(BuildPhase {
                                name: name.to_string(),
                                duration_seconds: (end_ts - start_ts).max(0.0),
                                skipped: None,
                                reason: None,
                                exit_code,
                            });
                            self.starts.remove(name);
                        }
                    }
                }
            }
        } else if let Some(rest) = payload.strip_prefix("CRBS_PHASE_SKIP ") {
            let skip_key = rest.trim().to_string();
            let duplicated = self.last_skip.as_deref() == Some(skip_key.as_str());
            self.last_skip = Some(skip_key);
            if duplicated {
                if let Some(ccache) = self.ccache.as_mut() {
                    ccache.feed_line(trimmed);
                }
                return;
            }
            let mut parts = rest.split_whitespace();
            if let Some(name) = parts.next() {
                let reason = parts.collect::<Vec<_>>().join(" ");
                self.phases.push(BuildPhase {
                    name: name.to_string(),
                    duration_seconds: 0.0,
                    skipped: Some(true),
                    reason: if reason.is_empty() {
                        None
                    } else {
                        Some(reason)
                    },
                    exit_code: None,
                });
            }
        } else if let Some(rest) = payload.strip_prefix("CRBS_RPMBUILD_PHASE ") {
            let mut parts = rest.split_whitespace();
            if let Some(name) = parts.next() {
                if let Some(ts_str) = parts.next() {
                    if let Ok(ts) = ts_str.parse::<f64>() {
                        self.rpm_timestamps.push((name.to_string(), ts));
                    }
                }
            }
        }

        // ccache 统计行与 phase 标记前缀互斥，仍每行过正则（与整日志扫描同口径）。
        if let Some(ccache) = self.ccache.as_mut() {
            ccache.feed_line(trimmed);
        }
    }

    fn finish(
        mut self,
        build_id: i64,
        srpm: &str,
        total_seconds: f64,
        shared_layer_hit: bool,
    ) -> BuildProfile {
        // 未匹配 START（无 END marker）：0.0 占位 + incomplete 标注，不把总时长
        // 误算到该 phase；HashMap 迭代序不定，按 name 排序保证输出逐字节确定。
        let mut incomplete: Vec<(String, f64)> = self.starts.into_iter().collect();
        incomplete.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, _start_ts) in incomplete {
            self.phases.push(BuildPhase {
                name,
                duration_seconds: 0.0,
                skipped: None,
                reason: Some("incomplete: no END marker".to_string()),
                exit_code: None,
            });
        }

        if !self.rpm_timestamps.is_empty() {
            if let Some(idx) = self.phases.iter().position(|p| p.name == "build") {
                let mut subphases = Vec::new();
                for window in self.rpm_timestamps.windows(2) {
                    let (name, start) = &window[0];
                    let (_, next_ts) = window[1];
                    subphases.push(BuildPhase {
                        name: format!("build-{}", name),
                        duration_seconds: (next_ts - *start).max(0.0),
                        skipped: None,
                        reason: None,
                        exit_code: None,
                    });
                }
                if let Some((name, start)) = self.rpm_timestamps.last() {
                    // build END 缺失时末子阶段结束时间不可定：total_seconds 是相对
                    // 时长而非 epoch，混算无意义——与未闭合 START 一致，incomplete、记 0。
                    let (duration_seconds, reason) = match self.build_end_ts {
                        Some(end_ts) => ((end_ts - *start).max(0.0), None),
                        None => (0.0, Some("incomplete: no END marker".to_string())),
                    };
                    subphases.push(BuildPhase {
                        name: format!("build-{}", name),
                        duration_seconds,
                        skipped: None,
                        reason,
                        exit_code: None,
                    });
                }
                self.phases.splice((idx + 1)..(idx + 1), subphases);
            }
        }

        let ccache = self.ccache.as_ref().and_then(|c| c.finish());

        BuildProfile {
            build_id,
            srpm: srpm.to_string(),
            total_seconds,
            shared_layer_hit,
            ccache,
            phases: self.phases,
        }
    }
}

/// 原子写入 `result_dir/profile.json`。
pub async fn write_profile(result_dir: &Path, profile: &BuildProfile) -> crate::Result<()> {
    let path = result_dir.join("profile.json");
    crate::engine::cache::write_json_atomic(&path, profile)
        .await
        .map_err(|e| crate::error::CrbsError::io_message(format!("write profile.json: {}", e)))?;
    Ok(())
}

/// 读取 `result_dir/profile.json`，文件不存在时返回 `None`。
pub async fn read_profile(result_dir: &Path) -> crate::Result<Option<BuildProfile>> {
    let path = result_dir.join("profile.json");
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => match serde_json::from_str::<BuildProfile>(&content) {
            Ok(profile) => Ok(Some(profile)),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Failed to parse profile.json");
                Ok(None)
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(crate::error::CrbsError::from_io_context(
            "read profile.json",
            e,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 内存版组装：整段 log 逐行喂 [`ProfileLineParser`]（与流式入口共用同一
    /// 状态机），供各单测驱动；生产无整字节载入入口，此壳仅测试域。
    fn parse_log(
        log: &str,
        build_id: i64,
        srpm: &str,
        total_seconds: f64,
        shared_layer_hit: bool,
        ccache_enabled: bool,
    ) -> BuildProfile {
        let mut parser = ProfileLineParser::new(ccache_enabled);
        for line in log.lines() {
            parser.feed_line(line);
        }
        parser.finish(build_id, srpm, total_seconds, shared_layer_hit)
    }

    #[test]
    fn parse_profile_basic() {
        let log = r#"
# CRBS_PHASE_START ccache-init 1718723456.000000000
some output
# CRBS_PHASE_END ccache-init 0 1718723456.500000000
# CRBS_PHASE_START install-srpm 1718723456.500000000
# CRBS_PHASE_END install-srpm 0 1718723456.800000000
# CRBS_PHASE_SKIP install-deps shared_layer
# CRBS_PHASE_START build 1718723456.800000000
# CRBS_PHASE_END build 0 1718723458.800000000
# CRBS_PHASE_START ccache-summary 1718723458.800000000
cache hit (direct): 102
cache hit (preprocessed): 0
cache miss: 18
# CRBS_PHASE_END ccache-summary 0 1718723459.000000000
"#;

        let profile = parse_log(log, 1, "tmux.src.rpm", 3.0, true, true);
        assert_eq!(profile.build_id, 1);
        assert!(profile.shared_layer_hit);
        assert_eq!(profile.phases.len(), 5);
        let install_srpm = profile
            .phases
            .iter()
            .find(|p| p.name == "install-srpm")
            .unwrap();
        assert!((install_srpm.duration_seconds - 0.3).abs() < 0.001);
        let install_deps = profile
            .phases
            .iter()
            .find(|p| p.name == "install-deps")
            .unwrap();
        assert_eq!(install_deps.skipped, Some(true));
        assert_eq!(install_deps.reason.as_deref(), Some("shared_layer"));
        let ccache = profile.ccache.unwrap();
        assert_eq!(ccache.cacheable_calls, 120);
        assert_eq!(ccache.cache_hits, 102);
        assert!((ccache.hit_rate - 0.85).abs() < 0.001);
    }

    #[test]
    fn parse_profile_without_ccache() {
        let log = "# CRBS_PHASE_START build 0.0\n# CRBS_PHASE_END build 0 1.0\n";
        let profile = parse_log(log, 42, "x.src.rpm", 1.0, false, false);
        assert!(profile.ccache.is_none());
        assert!(!profile.shared_layer_hit);
    }

    #[test]
    fn slowest_phase_returns_max() {
        let profile = BuildProfile {
            build_id: 42,
            srpm: "x.src.rpm".into(),
            total_seconds: 10.0,
            shared_layer_hit: false,
            ccache: None,
            phases: vec![
                BuildPhase {
                    name: "a".into(),
                    duration_seconds: 1.0,
                    skipped: None,
                    reason: None,
                    exit_code: None,
                },
                BuildPhase {
                    name: "b".into(),
                    duration_seconds: 5.0,
                    skipped: None,
                    reason: None,
                    exit_code: None,
                },
            ],
        };
        assert_eq!(profile.slowest_phase(), Some(("b", 5.0)));
    }

    #[test]
    fn parse_profile_subphases() {
        let log = r#"
# CRBS_PHASE_START build 0.0
CRBS_RPMBUILD_PHASE prep 1.0
prep output
CRBS_RPMBUILD_PHASE build 2.0
build output
CRBS_RPMBUILD_PHASE install 5.0
install output
# CRBS_PHASE_END build 0 7.0
"#;

        let profile = parse_log(log, 42, "x.src.rpm", 7.0, false, false);
        let build = profile.phases.iter().find(|p| p.name == "build").unwrap();
        assert!((build.duration_seconds - 7.0).abs() < 0.001);

        let names: Vec<_> = profile.phases.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["build", "build-prep", "build-build", "build-install"]
        );

        let prep = profile
            .phases
            .iter()
            .find(|p| p.name == "build-prep")
            .unwrap();
        assert!((prep.duration_seconds - 1.0).abs() < 0.001);
        let build_sub = profile
            .phases
            .iter()
            .find(|p| p.name == "build-build")
            .unwrap();
        assert!((build_sub.duration_seconds - 3.0).abs() < 0.001);
        let install = profile
            .phases
            .iter()
            .find(|p| p.name == "build-install")
            .unwrap();
        assert!((install.duration_seconds - 2.0).abs() < 0.001);
    }

    #[test]
    fn parse_profile_subphases_with_check() {
        let log = r#"
# CRBS_PHASE_START build 10.0
CRBS_RPMBUILD_PHASE prep 11.0
CRBS_RPMBUILD_PHASE build 12.0
CRBS_RPMBUILD_PHASE install 13.0
CRBS_RPMBUILD_PHASE check 14.0
# CRBS_PHASE_END build 0 20.0
"#;

        let profile = parse_log(log, 42, "x.src.rpm", 20.0, false, false);
        let names: Vec<_> = profile.phases.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "build",
                "build-prep",
                "build-build",
                "build-install",
                "build-check"
            ]
        );
        let check = profile
            .phases
            .iter()
            .find(|p| p.name == "build-check")
            .unwrap();
        assert!((check.duration_seconds - 6.0).abs() < 0.001);
    }

    /// build END 缺失：末子阶段标 incomplete、记 0，不把相对时长 total_seconds 当 epoch 混算。
    #[test]
    fn parse_profile_last_subphase_incomplete_without_build_end() {
        let log = r#"
# CRBS_PHASE_START build 0.0
CRBS_RPMBUILD_PHASE prep 1.0
CRBS_RPMBUILD_PHASE build 2.0
"#;

        let profile = parse_log(log, 42, "x.src.rpm", 7.0, false, false);
        let prep = profile
            .phases
            .iter()
            .find(|p| p.name == "build-prep")
            .unwrap();
        assert!((prep.duration_seconds - 1.0).abs() < 0.001);
        let last = profile
            .phases
            .iter()
            .find(|p| p.name == "build-build")
            .unwrap();
        assert_eq!(last.duration_seconds, 0.0);
        assert_eq!(last.reason.as_deref(), Some("incomplete: no END marker"));
    }

    /// 流式入口与内存入口必须产出相同 profile（同一状态机的两个壳）。
    #[tokio::test]
    async fn parse_profile_from_log_file_matches_in_memory_parser() {
        let log = r#"
# CRBS_PHASE_START ccache-init 100.0
# CRBS_PHASE_END ccache-init 0 100.5
# CRBS_PHASE_SKIP install-deps shared_layer
# CRBS_PHASE_START build 100.5
CRBS_RPMBUILD_PHASE prep 101.0
CRBS_RPMBUILD_PHASE install 102.0
cache hit (direct): 7
cache hit (preprocessed): 3
cache miss: 10
# CRBS_PHASE_END build 0 105.0
"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("build.log");
        tokio::fs::write(&path, log).await.unwrap();

        let from_file = parse_profile_from_log_file(&path, 7, "x.src.rpm", 5.0, true, true)
            .await
            .unwrap();
        let from_memory = parse_log(log, 7, "x.src.rpm", 5.0, true, true);
        assert_eq!(from_file, from_memory);
        assert_eq!(from_file.ccache.unwrap().cache_hits, 10);
    }

    /// 防御：SKIP 标记双写不得产生重复 phase；不同内容的 SKIP 不受影响。
    #[test]
    fn parse_profile_dedups_repeated_skip_markers() {
        let dup = "# CRBS_PHASE_SKIP install-deps shared_layer\n# CRBS_PHASE_SKIP install-deps shared_layer\n";
        let profile = parse_log(dup, 42, "x.src.rpm", 1.0, true, false);
        assert_eq!(profile.phases.len(), 1);
        assert_eq!(profile.phases[0].name, "install-deps");

        let distinct = "# CRBS_PHASE_SKIP install-deps shared_layer\n# CRBS_PHASE_SKIP ccache-init ccache_disabled\n";
        let profile = parse_log(distinct, 42, "x.src.rpm", 1.0, true, false);
        assert_eq!(profile.phases.len(), 2);
    }

    /// 时间线解析：START/END/SKIP 全覆盖，顺序 = 标记出现序（含噪声行）。
    #[test]
    fn parse_phase_markers_returns_spans_in_marker_order() {
        let log = "\
some bootstrap noise
# CRBS_PHASE_START ccache-init 100.0
ccache output
# CRBS_PHASE_END ccache-init 0 100.5
# CRBS_PHASE_SKIP install-deps shared_layer
# CRBS_PHASE_START build 100.5
rpmbuild output
# CRBS_PHASE_END build 2 105.0
";
        let spans = parse_phase_markers(log);
        let names: Vec<&str> = spans.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["ccache-init", "install-deps", "build"]);

        assert_eq!(spans[0].line, 2);
        assert_eq!(spans[1].line, 5);
        assert_eq!(spans[2].line, 6);

        assert_eq!(spans[0].state(), "done");
        assert!((spans[0].elapsed_seconds(0.0) - 0.5).abs() < 1e-9);
        assert_eq!(spans[0].exit_code, Some(0));

        assert_eq!(spans[1].state(), "skipped");
        assert_eq!(spans[1].reason.as_deref(), Some("shared_layer"));
        assert_eq!(spans[1].elapsed_seconds(999.0), 0.0);

        assert_eq!(spans[2].state(), "failed");
        assert_eq!(spans[2].exit_code, Some(2));
        assert!((spans[2].elapsed_seconds(0.0) - 4.5).abs() < 1e-9);
    }

    /// 时间线解析：最后 START 无 END → running，elapsed 用 now-start。
    #[test]
    fn parse_phase_markers_marks_unclosed_start_as_running() {
        let log = "# CRBS_PHASE_START install-srpm 200.0\n# CRBS_PHASE_END install-srpm 0 201.0\n# CRBS_PHASE_START build 201.0\n";
        let spans = parse_phase_markers(log);
        assert_eq!(spans[0].state(), "done");
        assert_eq!(spans[1].state(), "running");
        assert_eq!(spans[1].end, None);
        assert!((spans[1].elapsed_seconds(203.5) - 2.5).abs() < 1e-9);
    }

    /// 乱序容忍（标记双写防御）：无 START 的 END 忽略；重复 START 刷新不新增；重复 SKIP 只记一次。
    #[test]
    fn parse_phase_markers_tolerates_out_of_order_and_duplicates() {
        let log = "# CRBS_PHASE_END ghost 0 10.0\n\
# CRBS_PHASE_START build 10.0\n\
# CRBS_PHASE_START build 12.0\n\
# CRBS_PHASE_SKIP ccache-init ccache_disabled\n\
# CRBS_PHASE_SKIP ccache-init ccache_disabled\n\
# CRBS_PHASE_END build 0 15.0\n";
        let spans = parse_phase_markers(log);
        assert_eq!(spans.len(), 2, "ghost END must be ignored: {spans:?}");
        assert_eq!(spans[0].name, "build");
        // 重复 START 取后值：duration = 15.0 - 12.0。
        assert!((spans[0].elapsed_seconds(0.0) - 3.0).abs() < 1e-9);
        // 行号锚同步刷新到后一个 START（第 3 行）。
        assert_eq!(spans[0].line, 3);
        assert_eq!(spans[1].name, "ccache-init");
        assert_eq!(spans[1].state(), "skipped");
        // 重复 SKIP 只记一次，行号记首个 SKIP 标记行。
        assert_eq!(spans[1].line, 4);
    }

    /// build span 内子阶段观测：Executing 记名+行号，Bad exit 归属标 failed 存原文。
    #[test]
    fn parse_phase_markers_collects_subphases_inside_build_span() {
        let log = "\
# CRBS_PHASE_START install-deps 10.0
Executing(%clean): /bin/sh -e /var/tmp/rpm-tmp.noise1
# CRBS_PHASE_START build 20.0
some output
Executing(%prep): /bin/sh -e /var/tmp/rpm-tmp.aaa
prep output
Executing(%build): /bin/sh -e /var/tmp/rpm-tmp.bbb
build output
Executing(%check): /bin/sh -e /var/tmp/rpm-tmp.ccc
check output
error: Bad exit status from /var/tmp/rpm-tmp.ccc (%check)
# CRBS_PHASE_END build 1 30.0
Executing(%install): /bin/sh -e /var/tmp/rpm-tmp.after
";
        let spans = parse_phase_markers(log);
        let build = spans.iter().find(|s| s.name == "build").unwrap();
        let names: Vec<&str> = build.sub.iter().map(|s| s.name.as_str()).collect();
        // build 前的 Executing(%clean)（无 span）与 END 后的 Executing(%install)（已闭合）不混入。
        assert_eq!(names, vec!["%prep", "%build", "%check"], "{build:?}");

        let prep = &build.sub[0];
        assert!(!prep.failed);
        assert_eq!(prep.line, 5);
        assert_eq!(prep.error_line, None);

        let check = &build.sub[2];
        assert!(check.failed);
        // 行号以 1 起：check 的 Executing 行在第 9 行。
        assert_eq!(check.line, 9);
        assert_eq!(
            check.error_line.as_deref(),
            Some("error: Bad exit status from /var/tmp/rpm-tmp.ccc (%check)")
        );
    }

    /// noarch 重试：失败 END 闭合首个 span 后，重试 START 产出独立第二 span——观测不串档。
    #[test]
    fn parse_phase_markers_retry_yields_fresh_build_span() {
        let log = "\
# CRBS_PHASE_START build 10.0
Executing(%prep): /bin/sh -e /var/tmp/rpm-tmp.first
# CRBS_PHASE_END build 1 12.0
# CRBS_PHASE_START build 20.0
Executing(%build): /bin/sh -e /var/tmp/rpm-tmp.second
# CRBS_PHASE_END build 0 25.0
";
        let spans = parse_phase_markers(log);
        let builds: Vec<&PhaseSpan> = spans.iter().filter(|s| s.name == "build").collect();
        assert_eq!(builds.len(), 2, "{spans:?}");
        let names: Vec<&str> = builds[0].sub.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["%prep"]);
        assert_eq!(builds[0].sub[0].line, 2);
        assert_eq!(builds[0].state(), "failed");
        let names: Vec<&str> = builds[1].sub.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["%build"]);
        assert_eq!(builds[1].sub[0].line, 5);
        assert_eq!(builds[1].state(), "done");
    }

    /// 真·重复 START（双写、无 END 夹隔）：复用 span 并清空旧观测——START 语义 = phase 从头开始。
    #[test]
    fn parse_phase_markers_resets_subphases_on_duplicate_start() {
        let log = "\
# CRBS_PHASE_START build 10.0
Executing(%prep): /bin/sh -e /var/tmp/rpm-tmp.first
# CRBS_PHASE_START build 12.0
Executing(%build): /bin/sh -e /var/tmp/rpm-tmp.second
# CRBS_PHASE_END build 0 25.0
";
        let spans = parse_phase_markers(log);
        let build = spans.iter().find(|s| s.name == "build").unwrap();
        let names: Vec<&str> = build.sub.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["%build"], "{build:?}");
        assert_eq!(build.sub[0].line, 4);
        assert!((build.start - 12.0).abs() < 1e-9);
        // span 行号锚随重复 START 刷新（第 3 行），与作废旧子阶段观测同语义。
        assert_eq!(build.line, 3);
    }
}
