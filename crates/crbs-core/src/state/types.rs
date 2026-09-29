// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 状态层行模型：构建/层记录与列投影、行转换。

use crate::types::BuildPriority;
use sqlx::any::AnyRow;

/// 单条构建记录。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BuildRecord {
    pub id: i64,
    pub product: String,
    pub pkg_name: String,
    pub name: String,
    pub version: String,
    pub release: String,
    pub phase: String,
    pub result_dir: Option<String>,
    pub srpm_path: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    #[serde(rename = "duration_seconds")]
    pub duration: Option<i64>,
    pub layer_digest: Option<String>,
    pub base_os_digest: Option<String>,
    pub backend: Option<String>,
    pub user: String,
    pub user_id: Option<i64>,
    pub crbs_pid: Option<i64>,
    pub arch: Option<String>,
    pub task_id: Option<i64>,
    /// RPM 文件名列表（相对 result_dir/RPMS）；detail 接口扫描补充，列表接口通常为空。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rpms: Vec<String>,
    pub signed: bool,
    pub priority: BuildPriority,
    /// 失败原因摘要（终态 failed 时由上报方写入，UI 详情页展示）。
    pub error_summary: Option<String>,
    /// 确定性模式标记：1 = 该构建在 deterministic 产品模式下执行（宏组 / env 基线 / 溯源硬门生效）。
    pub deterministic: bool,
    /// 发布轴生效值（提交时快照）：false = 产物不进产品 repo 候选集（逐构建收紧）。
    #[serde(default)]
    pub repo_publish: bool,
    /// 消费轴生效值（提交时合流快照：产品可见性 ∧ 产品 repo-consume ∧ 逐构建收紧）：
    /// false = 派发不注入产品 repo。旧记录缺列时按默认消费处理。
    #[serde(default = "default_true")]
    pub repo_consume: bool,
    /// 血缘锚：输入 SRPM 原样字节的 sha256，任务内全部架构子构建共享同一值。
    /// deterministic 产品由 hub 在 start_build 写入，其余 None；比对侧不消费本值（比对锚是 unsigned_sha256）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_srpm_sha256: Option<String>,
    // ===== 资源可观测字段（终态采集，缺采集 = None）=====
    // 放置需求声明（req_min_*）：提交时随 BuildInsert 落列，未声明 = NULL。
    /// 实测峰值内存（cgroup memory.peak 口径，KB）；proc 口径无此值。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_rss_kb: Option<i64>,
    /// 采集包络峰值内存（含页缓存，KB）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_total_kb: Option<i64>,
    /// 构建进程树 CPU 累计时间（秒）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_secs: Option<f64>,
    /// CPU 利用率 p90（核）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_p90_cores: Option<f64>,
    /// 构建期磁盘写入字节（cgroup io.stat / proc 差分）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_wbytes: Option<i64>,
    /// cgroup memory.events oom_kill 检出（`None` = 未采集，proc 口径恒 None）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oom_killed: Option<bool>,
    /// 采样口径：`cgroup` / `proc`（列 CHECK 收敛，详见 schema）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_backend: Option<String>,
    /// 采样节点核数（peak_rss 与 `-j$(nproc)` 并行度耦合的口径注记）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_ncpu: Option<i64>,
    /// 构建自身 tmpfs 实例占用峰值 KB（build_tmpfs 关闭 / 缺观测 = None）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_tmpfs_kb: Option<i64>,
    /// 放置需求声明：最小内存 KB / 最小核数 / 最小可用磁盘 KB（提交时落列）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub req_min_mem_kb: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub req_min_ncpu: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub req_min_disk_kb: Option<i64>,
}

/// `serde(default)` 助手：布尔列默认 true（repo_consume 生效值默认消费）。
fn default_true() -> bool {
    true
}

/// builds 表的标准查询列，与 [`build_record_from_row`] 一一对应。
/// `"user" AS "user"`：USER 是 PG 保留字，列名与别名均须加引号（SQLite 双引号别名同法），别名确保 row.get("user") 命中。
pub(crate) const BUILD_COLUMNS: &str = "id, product, pkg_name, name, version, release, phase, result_dir, srpm_path, layer_digest, base_os_digest, backend, \"user\" AS \"user\", user_id, crbs_pid, started_at, completed_at, duration, signed, priority, arch, task_id, error_summary, deterministic, repo_publish, repo_consume, canonical_srpm_sha256, peak_rss_kb, peak_total_kb, cpu_secs, cpu_p90_cores, disk_wbytes, oom_killed, sample_backend, sample_ncpu, peak_tmpfs_kb, req_min_mem_kb, req_min_ncpu, req_min_disk_kb";

/// 从包含 [`BUILD_COLUMNS`] 的行构造 [`BuildRecord`]；`rpms` 留空，由调用方按需从结果目录补充。
pub(crate) fn build_record_from_row(r: &AnyRow) -> BuildRecord {
    use sqlx::Row as _;
    BuildRecord {
        id: r.get("id"),
        product: r.get("product"),
        pkg_name: r.get("pkg_name"),
        name: r.get("name"),
        version: r.get("version"),
        release: r.get("release"),
        phase: r.get("phase"),
        result_dir: r.get("result_dir"),
        srpm_path: r.get("srpm_path"),
        started_at: r.get("started_at"),
        completed_at: r.get("completed_at"),
        duration: r.get("duration"),
        layer_digest: r.get("layer_digest"),
        base_os_digest: r.get("base_os_digest"),
        backend: r.get("backend"),
        user: r.get("user"),
        user_id: r.get("user_id"),
        crbs_pid: r.get("crbs_pid"),
        rpms: Vec::new(),
        signed: r.get::<i64, _>("signed") != 0,
        priority: r.get::<i64, _>("priority") as BuildPriority,
        arch: r.get("arch"),
        task_id: r.get("task_id"),
        error_summary: r.get("error_summary"),
        deterministic: r.get::<i64, _>("deterministic") != 0,
        repo_publish: r.get::<i64, _>("repo_publish") != 0,
        repo_consume: r.get::<i64, _>("repo_consume") != 0,
        canonical_srpm_sha256: r.get("canonical_srpm_sha256"),
        peak_rss_kb: r.get("peak_rss_kb"),
        peak_total_kb: r.get("peak_total_kb"),
        cpu_secs: r.get("cpu_secs"),
        cpu_p90_cores: r.get("cpu_p90_cores"),
        disk_wbytes: r.get("disk_wbytes"),
        oom_killed: r.get::<Option<i64>, _>("oom_killed").map(|v| v != 0),
        sample_backend: r.get("sample_backend"),
        sample_ncpu: r.get("sample_ncpu"),
        peak_tmpfs_kb: r.get("peak_tmpfs_kb"),
        req_min_mem_kb: r.get("req_min_mem_kb"),
        req_min_ncpu: r.get("req_min_ncpu"),
        req_min_disk_kb: r.get("req_min_disk_kb"),
    }
}

/// 从 layers 标准列行构造 [`LayerRecord`]（list_layers_for_gc / list_leaked_layers 共用）。
pub(crate) fn layer_record_from_row(r: &AnyRow) -> LayerRecord {
    use sqlx::Row as _;
    LayerRecord {
        digest: r.get("digest"),
        path: r.get("path"),
        product: r.get("product"),
        status: r.get("status"),
        ref_count: r.get("ref_count"),
        created_at: r.get("created_at"),
        scheduled_gc_at: r.get("scheduled_gc_at"),
    }
}

/// 构建记录插入参数。Default 的 phase 取 'pending'——派生 Default 的 `""` 会被表 CHECK 约束拒绝。
#[derive(Debug, Clone)]
pub struct BuildInsert<'a> {
    pub product: &'a str,
    pub pkg_name: &'a str,
    pub phase: &'a str,
    pub result_dir: Option<&'a str>,
    pub layer_digest: Option<&'a str>,
    pub base_os_digest: Option<&'a str>,
    pub backend: &'a str,
    pub user: &'a str,
    pub user_id: Option<i64>,
    pub crbs_pid: Option<i64>,
    pub priority: BuildPriority,
    pub arch: Option<&'a str>,
    /// 调度宿主约束 CSV（仅 arch='noarch' 行使用，语义见 schema 列注；
    /// 架构包与无偏好产品传 None）。
    pub host_arches: Option<&'a str>,
    /// 发布轴生效值（提交时快照）：false = 产物不进产品 repo 候选集
    ///（逐构建收紧：--no-publish / reproduce 隔离）。Default = true（默认发布）。
    pub repo_publish: bool,
    /// 消费轴生效值（提交时合流快照：产品可见性 public ∧ 产品 repo-consume
    /// 未关闭 ∧ 未逐构建收紧 --no-consume）。Default = true（默认消费）。
    pub repo_consume: bool,
    /// 放置契约下限（提交时解析快照，单位 KB/核）：声明落列无害，硬下限
    /// 消费受 resource_requirements_enabled 开关。Default 全 None。
    pub req_min_mem_kb: Option<i64>,
    pub req_min_ncpu: Option<i64>,
    pub req_min_disk_kb: Option<i64>,
    pub task_id: Option<i64>,
}

impl<'a> Default for BuildInsert<'a> {
    fn default() -> Self {
        Self {
            product: "",
            pkg_name: "",
            phase: "pending",
            result_dir: None,
            layer_digest: None,
            base_os_digest: None,
            backend: "",
            user: "",
            user_id: None,
            crbs_pid: None,
            priority: BuildPriority::default(),
            arch: None,
            host_arches: None,
            repo_publish: true,
            repo_consume: true,
            req_min_mem_kb: None,
            req_min_ncpu: None,
            req_min_disk_kb: None,
            task_id: None,
        }
    }
}

/// 产品下同 pkg_name 的活跃构建引用（提交去重短路）；由 `active_builds_for_pkg_names` 返回，供 server 拼 409 冲突消息。
#[derive(Debug, Clone)]
pub struct ActiveBuildRef {
    pub pkg_name: String,
    pub build_id: i64,
    pub phase: String,
    pub task_id: Option<i64>,
}

/// 单层记录。
#[derive(Debug, Clone)]
pub struct LayerRecord {
    pub digest: String,
    pub path: String,
    pub product: String,
    pub status: String,
    pub ref_count: i64,
    pub created_at: Option<String>,
    pub scheduled_gc_at: Option<String>,
}

/// 构建产物中包含的 RPM 包记录（canonical 数据存储在 result_dir/build_packages.json）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BuildPackage {
    pub build_id: i64,
    pub nevra: String,
    pub sha256: String,
    pub repo: Option<String>,
    pub url: Option<String>,
}

/// 用户可见的任务记录。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TaskRecord {
    pub id: i64,
    pub product: String,
    pub pkg_name: String,
    pub name: String,
    pub version: String,
    pub release: String,
    pub user: String,
    pub phase: String,
    pub priority: BuildPriority,
    pub srpm_path: Option<String>,
    pub result_dir: Option<String>,
    pub submitted_at: Option<String>,
    pub completed_at: Option<String>,
    #[serde(rename = "duration_seconds")]
    pub duration: Option<i64>,
    /// 批次内全部包的 NVR 列表（提交序）；列为 NULL 或非法时为空列表，单包展示回退 `pkg_name`。
    #[serde(default)]
    pub pkg_names: Vec<String>,
}

impl TaskRecord {
    /// 列表页展示用包标签：单包返回 NVR，多包返回 `首包 NVR +N`。
    pub fn pkg_label(&self) -> String {
        match self.pkg_names.len() {
            0 => self.pkg_name.clone(),
            1 => self.pkg_names[0].clone(),
            n => format!("{} +{}", self.pkg_names[0], n - 1),
        }
    }
}

/// 任务记录插入参数。Default 的 phase 取 'pending'——派生 Default 的 `""` 会被表 CHECK 约束拒绝。
#[derive(Debug, Clone)]
pub struct TaskInsert<'a> {
    pub product: &'a str,
    pub pkg_name: &'a str,
    pub user: &'a str,
    pub user_id: Option<i64>,
    pub phase: &'a str,
    pub priority: BuildPriority,
    pub srpm_path: Option<&'a str>,
    pub result_dir: Option<&'a str>,
    /// task 级构建选项 JSON（不含 arch），供 rebuild 重放。
    pub request_json: Option<&'a str>,
    /// 批次全部包的 NVR JSON 数组（提交序）。
    pub pkg_names: Option<&'a str>,
}

impl<'a> Default for TaskInsert<'a> {
    fn default() -> Self {
        Self {
            product: "",
            pkg_name: "",
            user: "",
            user_id: None,
            phase: "pending",
            priority: BuildPriority::default(),
            srpm_path: None,
            result_dir: None,
            request_json: None,
            pkg_names: None,
        }
    }
}

/// rebuild 重放所需的 task 档案（不含 API 展示字段）。
#[derive(Debug, Clone)]
pub struct TaskRebuildInfo {
    pub product: String,
    pub user: String,
    pub priority: BuildPriority,
    pub result_dir: Option<String>,
    /// task 级选项 JSON；为 NULL 时无法重建。
    pub request_json: Option<String>,
    /// 任务显示名（NEVR 真名，不带 .src.rpm；复现任务沿用此名）。
    pub pkg_name: String,
}

/// 产品内单源码包（`builds.name`）的最近一次构建摘要：产品页画像包列表的
/// "最新构建"列（版本只是历史维度，画像键不含版本）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LatestSourceBuild {
    pub source_name: String,
    /// 最近一次构建的构建 id（详情页链接）。
    pub id: i64,
    /// 最近一次构建的 NVR/NEVR。
    pub pkg_name: String,
    pub arch: Option<String>,
    pub phase: String,
    pub completed_at: Option<String>,
}

/// 任务分组汇总：pkg_name 为分组键（完整 NVR 走 `list_nvr_groups`，基础包名走 `list_name_groups`），字段取最新一次任务。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NvrGroupSummary {
    pub pkg_name: String,
    pub attempts: i64,
    pub latest_task_id: i64,
    pub product: String,
    pub phase: String,
    pub user: String,
    pub submitted_at: Option<String>,
}

/// NVR 分组查询过滤条件（复杂配置用 struct 参数）。
#[derive(Debug, Default)]
pub struct NvrGroupFilter<'a> {
    pub product: Option<&'a str>,
    pub user: Option<&'a str>,
    /// 包名过滤，语义随查询粒度：`list_nvr_groups` 按 pkg_name 前缀匹配（兼容粘贴完整包名）；
    /// `list_name_groups` 按 name 列子串匹配（同 `list_package_names` 的 /ui/packages 列表页口径）。
    pub name: Option<&'a str>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    /// 可选的产品可见性白名单：`Some(list)` 在 inner 子查询追加
    /// `(product IN (...) OR product NOT IN (SELECT name FROM products))`，孤儿豁免
    ///（已删产品的 attempts 对所有人可见）由 NOT IN 子句承载；`Some(空)` 仅拼孤儿豁免
    ///——现存产品全不可见但孤儿仍可见（非 `1=0`，与 `compute_visible_products` 空名单边界一致）；
    /// `None` 不过滤（admin / operator bypass）。owned `Vec<String>`：server 层返回 owned，避免生命周期跨调用栈。
    pub visible_products: Option<Vec<String>>,
}

/// 用于 server 崩溃恢复的 pending 构建请求信息。
#[derive(Debug, Clone)]
pub struct PendingBuildInfo {
    pub id: i64,
    pub product: String,
    pub srpm_path: String,
    pub request_json: String,
    pub crbs_pid: Option<i64>,
}

/// 从包含 `id, product, srpm_path, request_json, crbs_pid` 的行构造 [`PendingBuildInfo`]。
pub(crate) fn pending_build_info_from_row(r: &AnyRow) -> PendingBuildInfo {
    use sqlx::Row as _;
    PendingBuildInfo {
        id: r.get("id"),
        product: r.get("product"),
        srpm_path: r.get("srpm_path"),
        request_json: r.get("request_json"),
        crbs_pid: r.get("crbs_pid"),
    }
}
