// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 构建日志上报。

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::state::AppState;

use super::require_own_worker;

/// report_logs 落盘 build.log 的单 build 容量上限（512MB）。
///
/// 终态截断之上的 pre-terminal 上限：认证 worker 可在构建期无限追加撑爆
/// 磁盘；超限拒绝追加（不截断现场），实时读取走 10MB FIFO 缓冲不受影响。
pub(super) const MAX_HUB_BUILD_LOG_BYTES: u64 = 512 * 1024 * 1024;

/// report_logs 路由 body limit 在单 chunk 语义上限之上的余量（64KiB）。
///
/// worker 发裸字节 chunk（无 JSON 信封，LogBatcher 单批 ≤ 64KiB + 4KiB - 1），
/// 端点语义上限即 [`crate::server::log_buffer::MAX_LOG_CHUNK_BYTES`]（1MB）。
/// 余量让"刚好超限"（≤ 上限 + 余量）仍到 handler 预检（400 带确切上限，
/// worker 4xx → ValidationFailed 不重试），明显超出才由 layer 直接 413——
/// 否则 `body: Bytes` 先整包缓冲才拒，失控 worker 每请求放大内存。
pub(super) const REPORT_LOGS_BODY_HEADROOM: usize = 64 * 1024;

pub(super) async fn report_logs(
    State(app): State<Arc<AppState>>,
    Path((worker_id, assignment_id)): Path<(i64, i64)>,
    auth: Option<axum::extract::Extension<AuthContext>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _ctx = require_own_worker(&auth, worker_id)?;

    // 幂等序号（可缺省：兼容未升级的 worker）。同一 chunk 的所有重试复用同一
    // 序号；已接受过的序号再次到达说明首次响应丢失，直接确认、不再追加。
    let log_seq = match headers.get("x-crbs-log-seq") {
        None => None,
        Some(v) => Some(
            v.to_str()
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .ok_or_else(|| ApiError::Validation("invalid X-Crbs-Log-Seq header".into()))?,
        ),
    };

    // 一次行查询取归属 / 终态 / build_id：行不存在 → 归属 403；init 任务
    // build_id 为 None 时跳过落盘仍 200。
    let (build_id, task_worker_id, _task_kind, task_status) = app
        .state_store
        .get_worker_task_meta(assignment_id)
        .await
        .map_err(ApiError::from)?;

    // 校验 assignment 确实属于该 worker，防止通过猜测 assignment_id 越界写入
    if task_worker_id != Some(worker_id) {
        return Err(ApiError::PermissionDenied(
            "assignment does not belong to worker".into(),
        ));
    }

    // 终态截断：终态后不再收日志 chunk——否则恶意 worker 无限追加令
    // build.log 无界增长；result 端点另有幂等终态检查。
    if task_status
        .as_deref()
        .is_some_and(|s| matches!(s, "completed" | "failed" | "cancelled"))
    {
        tracing::warn!(
            assignment_id = %assignment_id,
            status = ?task_status,
            "log chunk rejected for terminal assignment"
        );
        return Err(ApiError::Conflict(
            "assignment already reached terminal state; log upload closed".into(),
        ));
    }

    // 幂等预检：序号 ≤ 已接受最大值的 chunk 是重试重放（首次响应丢失），
    // 直接确认、不再追加——过期的 `has/register`、写盘与缓冲都不再执行。
    if let Some(seq) = log_seq {
        let accepted = app
            .hub_log_chunk_seq
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&assignment_id)
            .copied()
            .unwrap_or(0);
        if seq <= accepted {
            tracing::debug!(
                assignment_id = %assignment_id,
                seq,
                accepted,
                "Duplicate log chunk ignored (idempotent retry)"
            );
            return Ok(Json(serde_json::json!({"accepted": true})));
        }
    }

    if let Some(id) = build_id {
        // 无论 body 是否为空都先注册（worker 开工发空 chunk 占位，实时流提前挂接）。
        //
        // 偏移重播种：hub 重启丢内存 LogBuffer，新建条目若 0 起编号会与磁盘
        // build.log 永久错位（补尾 / 补读 / SSE 事件 id 全读错位）。`!has` 且
        // 文件已存在 → 以文件长度作 base；不存在 → 真首启 0 起。
        //
        // `!has` 与注册无原子性，但同 build chunk 由单 worker LogBatcher 串行
        // 发出不会并发进入；register_with_base 对已存在条目 no-op 纵深防御。
        // 残留窗口：reclaim 后被剥夺 worker 发送至预算耗尽——前缀对齐靠
        // offset 校验保持，仅内容可能交错。
        if app.log_buffer.has(id) {
            // 本进程已见过该 build：条目就位，register 幂等 no-op。
            app.log_buffer.register(id);
        } else {
            let seed_log_path = app.artifact_dir().join(id.to_string()).join("build.log");
            match tokio::fs::metadata(&seed_log_path).await {
                Ok(meta) => app.log_buffer.register_with_base(id, meta.len()),
                // 文件不存在 = 真首启，0 起编号。
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => app.log_buffer.register(id),
                // stat 异常（权限 / IO）不能按 0 播种（会复制要消灭的错位）：
                // 同步重试一次按文件长度播种，仍失败才降级 0 起并 warn 留痕。
                Err(e) => {
                    tracing::warn!(
                        build_id = %id,
                        path = %seed_log_path.display(),
                        error = %e,
                        "Log seed stat failed; retrying synchronously before 0-base fallback"
                    );
                    let retry_path = seed_log_path.clone();
                    match tokio::task::spawn_blocking(move || std::fs::metadata(retry_path)).await {
                        Ok(Ok(meta)) => app.log_buffer.register_with_base(id, meta.len()),
                        _ => app.log_buffer.register(id),
                    }
                }
            }
        }
        if !body.is_empty() {
            // 单 chunk 上限预检（与 LogBuffer::append 拒收同限）：显式 400 让
            // worker 立即感知（4xx → ValidationFailed 不重试，走缺口占位）。
            // 只覆盖单 chunk 超限；512MB 落盘 cap 是独立维度（见 over_cap 分支）。
            if body.len() > crate::server::log_buffer::MAX_LOG_CHUNK_BYTES {
                return Err(ApiError::Validation(format!(
                    "log chunk exceeds single-chunk limit of {} bytes",
                    crate::server::log_buffer::MAX_LOG_CHUNK_BYTES
                )));
            }

            // 双写不变量：durable 先行、缓冲后进——按文件实际推进的字节数
            //（durable_len）决定进 LogBuffer 的内容，两侧 offset 一字节对齐；
            // 失败不进缓冲，否则缓冲编号超前文件，offset seek 的消费端
            //（补读 / 补尾 / SSE / 重播种）全读错位。两个写前失败分支（目录
            // 预备 / open）回 503：chunk 未落盘，worker 5xx → Network 重试
            // 重放同 chunk（零错位）。write 零进展（文件端 == 缓冲 offset，
            // 如 sustained ENOSPC）同 503；有前缀（ENOSPC 中途截断）保持 200
            //——已落盘前缀按文件长度收进缓冲对齐，503 会致重放重复前缀。
            let mut durable_len = 0usize;

            // 双写 artifact_dir/{build_id}/build.log（失败构建无产物上传，这是
            // 唯一 durable 副本）。保留策略（bounded）：终态截断（终态后入口
            // 409）；pre-terminal 上限（超 MAX_HUB_BUILD_LOG_BYTES 拒绝追加）；
            // 结果 GC 联动（结果目录被删时一并删）；孤儿兜底（DB 行 prune 后
            // 由孤儿 sweep 清理，24h mtime 宽限）。
            let artifact_dir = app.artifact_dir().join(id.to_string());
            // 目录预备记忆化：create_dir_all + 递归 chown/chmod 每 build 一次。
            // 标记在 create_dir_all 成功后插入，chown/chmod 失败不阻止标记
            //（warn-only；阻止会致每 chunk 重复递归重试）；create_dir_all 失败
            // 不标记，warn + 503（worker 重放同 chunk）。i64 自增不复用 id，
            // 标记无需失效；4096 封顶 + clear（clear 后最坏重复预备一次，幂等）。
            let mut dir_ready = {
                let prepared = app
                    .hub_log_dir_prepared
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                prepared.contains(&id)
            };
            if !dir_ready {
                if let Err(e) = tokio::fs::create_dir_all(&artifact_dir).await {
                    tracing::warn!(build_id = %id, error = %e, "Failed to create artifact dir for log persistence");
                    // 写前失败（目录预备）不回 200：503 走 worker 5xx →
                    // Network 重试重放同 chunk（零错位）；固定文案对齐
                    // DatabaseUnavailable 503 口径（不回传底层细节）。
                    return Err(ApiError::ServiceUnavailable(
                        "log persistence unavailable".into(),
                    ));
                } else {
                    {
                        let mut prepared = app
                            .hub_log_dir_prepared
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        if prepared.len() >= 4096 {
                            prepared.clear();
                        }
                        prepared.insert(id);
                    }
                    // recursive chown + chmod 2770（dir 带 SGID，子文件继承 crbs 组）；
                    // walker 对 file 走 mode & 0o666，SGID 不会错设到 file。
                    crbs_core::privilege::chown_to_crbs_group_async(
                        &artifact_dir,
                        true,
                        "artifact_dir",
                    )
                    .await;
                    if let Err(e) =
                        crbs_core::privilege::chmod_async(&artifact_dir, 0o2770, true).await
                    {
                        tracing::warn!(build_id = %id, error = %e, "chmod 2770 artifact_dir recursive failed; permission invariant not enforced");
                    }
                    dir_ready = true;
                }
            }
            if dir_ready {
                let log_path = artifact_dir.join("build.log");

                // 容量上限：文件已超上限则拒绝追加（不截断），每 build warn
                // 一次；内存 LogBuffer 不受影响（10MB FIFO）。
                //
                // cap 长度分歧按设计保留：cap 后文件冻结 512MB、缓冲照收——
                // 仅长度分歧、内容零错位（文件 [0, cap) 恒对齐），消费端 EOF
                // 有界（补读读短即跳 / 补尾守卫收尾 / 越界 400）；不进缓冲会把
                // 实时 tail 一并降级（实时可见性优先于长度记账一致）。
                let over_cap = match tokio::fs::metadata(&log_path).await {
                    Ok(meta) => meta.len() >= MAX_HUB_BUILD_LOG_BYTES,
                    Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => false,
                    Err(_) => false, // 元数据不可读时放行：open 阶段会给出真实错误
                };
                if over_cap {
                    let mut warned = app
                        .hub_log_cap_warned
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    // 封顶防无界：溢出 clear 后最坏重复 warn 一次，无正确性影响。
                    if warned.len() >= 4096 {
                        warned.clear();
                    }
                    let first = warned.insert(id);
                    if first {
                        tracing::warn!(
                            build_id = %id,
                            limit_bytes = MAX_HUB_BUILD_LOG_BYTES,
                            "build.log exceeds hub persistence cap; refusing further appends"
                        );
                    }
                    // 设计分歧（见上注释）：文件不动，缓冲照收全量。
                    durable_len = body.len();
                } else {
                    // 0660 权限不变量：root hub 落的 build.log 默认 0644/root:root，
                    // 组内身份读取受限；目录 SGID 已保证组继承，无需 chown。
                    // `.mode(0o660)` 受 umask 削减，open 后显式 set_permissions
                    // 收口，逐 chunk 幂等重设（存量 0640 也随下次追加收口）。
                    match tokio::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .mode(0o660)
                        .open(&log_path)
                        .await
                    {
                        Ok(mut file) => {
                            use std::os::unix::fs::PermissionsExt;
                            if let Err(e) = file
                                .set_permissions(std::fs::Permissions::from_mode(0o660))
                                .await
                            {
                                // 每 build 只 warn 一次：重设幂等、失败逐 chunk
                                // 复现，逐次 warn 纯噪音；封顶 + clear 防无界。
                                let first = {
                                    let mut warned = app
                                        .hub_log_chmod_warned
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner());
                                    if warned.len() >= 4096 {
                                        warned.clear();
                                    }
                                    warned.insert(id)
                                };
                                if first {
                                    tracing::warn!(
                                        build_id = %id,
                                        path = %log_path.display(),
                                        error = %e,
                                        "failed to chmod build.log to 0660 (perms may not be effective)"
                                    );
                                }
                            }
                            use tokio::io::AsyncWriteExt;
                            // write_all Ok 只表示字节入队阻塞池，flush 才真正
                            // 落盘——记账以 flush 落点为准，否则重开"文件滞后"
                            // 补读瞬态。
                            let mut write_res = file.write_all(&body).await;
                            if write_res.is_ok() {
                                write_res = file.flush().await;
                            }
                            match write_res {
                                Ok(()) => durable_len = body.len(),
                                Err(e) => {
                                    tracing::warn!(build_id = %id, error = %e, "Failed to append to build.log");
                                    // 部分写入（ENOSPC 中途截断）：已推进字节是
                                    // 本 chunk 合法前缀，按"文件现长 - 缓冲
                                    // offset"取前缀进缓冲对齐；saturating 防外部
                                    // 截断倒挂（按 0 处理）。取现长用仍在手的
                                    // file 句柄（fstat 同 fd）——path-stat 可能读到
                                    // 被 rename/unlink 的路径（错位窗口；本分支
                                    // 唯一无测试覆盖，ENOSPC 中途短写难构造）。
                                    durable_len = match file.metadata().await {
                                        Ok(meta) => {
                                            let buffered =
                                                app.log_buffer.total_size(id).unwrap_or(0) as u64;
                                            let prefix = (meta.len().saturating_sub(buffered)
                                                as usize)
                                                .min(body.len());
                                            if prefix == 0 {
                                                // 零进展子形态（文件端 == 缓冲
                                                // offset）：重放零错位，同写前失败
                                                // 回 503 触发 worker 重试。前缀 > 0
                                                // 不可 503——重放会重复前缀，保持 200。
                                                return Err(ApiError::ServiceUnavailable(
                                                    "log persistence unavailable".into(),
                                                ));
                                            }
                                            prefix
                                        }
                                        // fstat 同错（fd 已坏）只能按 0：已落盘
                                        // 前缀不进缓冲，下一 chunk 错位 p 字节——
                                        // 与外部截断/替换 build.log 同类，不猜
                                        // 前缀、不重试写。
                                        Err(_) => 0,
                                    };
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(build_id = %id, error = %e, "Failed to open build.log for append");
                            // 写前失败（open）同目录预备分支：503 触发 worker
                            // 重放；有前缀短写保持 200、零进展同回 503（见上分流）。
                            return Err(ApiError::ServiceUnavailable(
                                "log persistence unavailable".into(),
                            ));
                        }
                    }
                }
            }
            // 落盘推进多少字节缓冲就收多少；0 时跳过 append——不通知不推进，
            // 下轮从同一偏移续写（零错位）。
            if durable_len > 0 {
                app.log_buffer.append(id, body.slice(..durable_len));
            }

            // 序号只在本次追加收口后推进：上面两条 503（未落盘）提前返回不
            // 记录，worker 重试同一 seq 可重新尝试；200（含短写前缀 / over_cap
            // 缓冲）记录，后续同 seq 重放被预检丢弃。
            if let Some(seq) = log_seq {
                let mut seqs = app
                    .hub_log_chunk_seq
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if seqs.len() >= 4096 {
                    seqs.clear();
                }
                seqs.insert(assignment_id, seq);
            }
        }
    }

    Ok(Json(serde_json::json!({"accepted": true})))
}
