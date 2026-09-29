// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建 API 数据类型：请求/响应结构与敏感字段脱敏。

use serde::{Deserialize, Serialize};

/// 构建提交响应：用户可见任务 ID、内部子构建 ID 列表与提交元信息。
#[derive(Serialize)]
pub struct BuildResponse {
    pub task_id: i64,
    pub ids: Vec<i64>,
    pub phase: &'static str,
    pub product: String,
    pub submitted_at: chrono::DateTime<chrono::Utc>,
    /// 任务显示名（NEVR 真名，不带 .src.rpm；复现任务沿用此名）。
    pub pkg_name: String,
    /// 提交期因 spec 架构约束（ExclusiveArch/ExcludeArch）跳过未创建的
    /// 子构建，格式 "pkg: arch (reason)"。恒存在（空 = 无跳过），
    /// 响应无此字段时客户端按空集解析。
    #[serde(default)]
    pub skipped_arches: Vec<String>,
    /// 放置契约下限回显（物化值，KB/核；未声明 = null）。恒输出三键（键集
    /// 稳定便于诊断）：CLI 据此检测"声明了但响应缺失"。
    pub req_min_mem_kb: Option<i64>,
    pub req_min_ncpu: Option<i64>,
    pub req_min_disk_kb: Option<i64>,
}

/// 构建列表查询参数：过滤（product / phase / name / arch / task_id /
/// srpm_sha256）与排序分页。`srpm_sha256` 为 SRPM 内容哈希精确匹配（16 进制串）。
#[derive(Debug, Default, Deserialize)]
pub struct ListQuery {
    pub product: Option<String>,
    pub phase: Option<String>,
    pub name: Option<String>,
    pub arch: Option<String>,
    pub task_id: Option<i64>,
    pub srpm_sha256: Option<String>,
    pub sort: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// 构建列表响应：过滤后总数与当前页记录（经 [`sanitize_build_record`] 脱敏，不含服务端绝对路径）。
#[derive(Serialize)]
pub struct BuildListResponse {
    pub total: usize,
    pub builds: Vec<crbs_core::BuildRecord>,
}

/// 构建记录的响应脱敏映射：`result_dir` / `srpm_path` 是服务端绝对路径，不回显（泄露
/// 服务端布局；取文件走 build_id 既有端点）；置 `None`（序列化为 `null`）而非删键：
/// 两键恒输出（无值置 null）：CLI `BuildRecord` 对应字段为 Option（serde 隐式默认，
/// null/缺键均落 None），恒输出是为键集稳定、便于诊断，非反序列化必需。
pub(crate) fn sanitize_build_record(mut record: crbs_core::BuildRecord) -> crbs_core::BuildRecord {
    record.result_dir = None;
    record.srpm_path = None;
    record
}

/// 构建取消响应：是否成功取消与提示消息。
#[derive(Serialize)]
pub struct CancelResponse {
    pub cancelled: bool,
    pub id: i64,
    pub message: String,
}

/// 构建优先级调整请求体。
#[derive(Deserialize)]
pub struct UpdatePriorityRequest {
    pub priority: crbs_core::BuildPriority,
}

/// 构建结果 diff 查询参数：against 指定对比基准构建。
#[derive(Deserialize)]
pub struct DiffQuery {
    pub against: String,
}

#[cfg(test)]
mod tests {
    use crbs_core::types::BuildRequest;
    use crbs_core::BuildOptions;

    #[test]
    fn build_request_deserializes_with_defaults() {
        let req: BuildRequest =
            serde_json::from_str(r#"{"product":"fedora","srpms":["/tmp/x.src.rpm"]}"#).unwrap();
        assert_eq!(req.product, "fedora");
        assert_eq!(req.srpms, vec!["/tmp/x.src.rpm"]);
        assert!(req.options.stage.is_none());
        assert!(req.options.ccache.is_none());
    }

    #[test]
    fn build_options_defaults_to_empty() {
        let opts: BuildOptions = serde_json::from_str("{}").unwrap();
        assert!(opts.backend.is_none());
    }

    /// 回显契约 serde：req_min_* 三键恒输出（未声明 = null，键集稳定便于
    /// 诊断），声明值如实回显物化 KB/核；CLI 侧"响应缺失"检测按缺键判定。
    #[test]
    fn build_response_always_serializes_req_min_keys() {
        let resp = super::BuildResponse {
            task_id: 5,
            ids: vec![21],
            phase: "pending",
            product: "fedora".into(),
            submitted_at: chrono::Utc::now(),
            pkg_name: "hello-1.0-1".into(),
            skipped_arches: Vec::new(),
            req_min_mem_kb: None,
            req_min_ncpu: Some(8),
            req_min_disk_kb: None,
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["req_min_mem_kb"], serde_json::json!(null));
        assert_eq!(json["req_min_ncpu"], serde_json::json!(8));
        assert_eq!(json["req_min_disk_kb"], serde_json::json!(null));
    }

    /// 资源字段非敏感（纯数量与口径枚举，无路径成分）：sanitize 只脱
    /// result_dir/srpm_path，资源字段原样保留（API 消费面）。
    #[test]
    fn sanitize_preserves_resource_fields() {
        let mut rec = crbs_core::BuildRecord {
            id: 1,
            product: "fedora".into(),
            pkg_name: "hello".into(),
            name: "hello".into(),
            version: "1.0".into(),
            release: "1".into(),
            phase: "succeeded".into(),
            result_dir: Some("/srv/crbs/results/1".into()),
            srpm_path: Some("/srv/crbs/srpms/hello.src.rpm".into()),
            started_at: None,
            completed_at: None,
            duration: None,
            layer_digest: None,
            base_os_digest: None,
            backend: None,
            user: "alice".into(),
            user_id: None,
            crbs_pid: None,
            rpms: Vec::new(),
            signed: false,
            priority: 0,
            arch: None,
            task_id: None,
            error_summary: None,
            deterministic: false,
            repo_publish: true,
            repo_consume: true,
            canonical_srpm_sha256: None,
            peak_rss_kb: Some(2_621_440),
            peak_total_kb: Some(524_288),
            cpu_secs: Some(42.5),
            cpu_p90_cores: Some(3.7),
            disk_wbytes: Some(1_236),
            oom_killed: Some(true),
            sample_backend: Some("cgroup".into()),
            sample_ncpu: Some(8),
            peak_tmpfs_kb: Some(65_536),
            req_min_mem_kb: None,
            req_min_ncpu: None,
            req_min_disk_kb: None,
        };
        let out = super::sanitize_build_record(rec.clone());
        assert_eq!(out.result_dir, None, "path fields must stay sanitized");
        assert_eq!(out.srpm_path, None);
        assert_eq!(out.peak_rss_kb, rec.peak_rss_kb);
        assert_eq!(out.peak_total_kb, rec.peak_total_kb);
        assert_eq!(out.cpu_secs, rec.cpu_secs);
        assert_eq!(out.cpu_p90_cores, rec.cpu_p90_cores);
        assert_eq!(out.disk_wbytes, rec.disk_wbytes);
        assert_eq!(out.oom_killed, rec.oom_killed);
        assert_eq!(out.sample_backend, rec.sample_backend);
        assert_eq!(out.sample_ncpu, rec.sample_ncpu);
        assert_eq!(out.peak_tmpfs_kb, rec.peak_tmpfs_kb);

        // 全 NULL 形态同样保留（None 原样透传，不误置值）。
        rec.peak_rss_kb = None;
        rec.oom_killed = None;
        let out = super::sanitize_build_record(rec);
        assert_eq!(out.peak_rss_kb, None);
        assert_eq!(out.oom_killed, None);
    }
}
