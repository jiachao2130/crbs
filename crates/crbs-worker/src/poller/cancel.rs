// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 在跑构建的取消登记与已执行 assignment 去重。

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use tokio_util::sync::CancellationToken;

/// 在跑构建的取消 token 注册表（assignment_id → CancellationToken）：心跳
/// 搭车的取消通知按 assignment_id 命中即触发对应构建的击杀路径。
/// std::sync::Mutex：纯内存操作，不跨 await 持锁；毒化经 `into_inner()`
/// 收回，注册表退化不弄死在跑构建。
#[derive(Clone, Default)]
pub(crate) struct CancelRegistry(Arc<Mutex<HashMap<i64, CancellationToken>>>);

impl CancelRegistry {
    /// 注册 assignment 的取消 token（poller 领到任务、child token 创建后）。
    pub(crate) fn insert(&self, assignment_id: i64, token: CancellationToken) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(assignment_id, token);
    }

    /// 触发取消：命中活 token 才 cancel 返回 true；未知/已取消返回 false——
    /// 调用方只打一次 info，重复通知幂等。条目不移除，由
    /// [`CancelRegistrationGuard`] 的 Drop 管理。
    pub(crate) fn cancel(&self, assignment_id: i64) -> bool {
        let map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(&assignment_id) {
            Some(token) if !token.is_cancelled() => {
                token.cancel();
                true
            }
            _ => false,
        }
    }

    fn remove(&self, assignment_id: i64) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&assignment_id);
    }

    /// 该 assignment 是否已注册（执行中）：hub 对响应丢失的 assignment 按
    /// running 行重投递，命中 = 本进程正在执行，须跳过二次 spawn。
    pub(crate) fn contains(&self, assignment_id: i64) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&assignment_id)
    }
}

/// 注册表条目生命周期 guard：构造即注册，Drop（含 panic）时移除。
pub(super) struct CancelRegistrationGuard {
    registry: CancelRegistry,
    assignment_id: i64,
}

impl CancelRegistrationGuard {
    pub(super) fn new(
        registry: CancelRegistry,
        assignment_id: i64,
        token: CancellationToken,
    ) -> Self {
        registry.insert(assignment_id, token);
        Self {
            registry,
            assignment_id,
        }
    }
}

impl Drop for CancelRegistrationGuard {
    fn drop(&mut self) {
        self.registry.remove(self.assignment_id);
    }
}

/// 已执行 assignment 的 FIFO 定容去重集合：succeeded 上报被 hub 接受后
/// 登记，派发前查重（kind 分流之前，build 与 init 共用）。与在途去重
/// （[`CancelRegistry`]，生命周期 = 执行期）并列——重投递恰在 guard 移除后
/// 到达时注册表必然 miss，无此集合会重执行同一 assignment（双构建 +
/// 双上传）。只记成功上报：失败/取消的重派是合法重试，不得去重。
#[derive(Clone, Default)]
pub(crate) struct ExecutedAssignments(pub(super) Arc<Mutex<VecDeque<i64>>>);

/// 容量：覆盖分钟级重投递竞态窗口内本进程完成量（capacity=4 稳态 ≈ 数小时吞吐）。
pub(super) const EXECUTED_ASSIGNMENTS_CAPACITY: usize = 1024;

impl ExecutedAssignments {
    /// 登记已完成并成功上报的 assignment（定容 FIFO，超界驱逐最老）。
    pub(crate) fn record(&self, assignment_id: i64) {
        let mut q = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if q.len() >= EXECUTED_ASSIGNMENTS_CAPACITY {
            q.pop_front();
        }
        if !q.contains(&assignment_id) {
            q.push_back(assignment_id);
        }
    }

    /// 该 assignment 是否已由本进程执行并成功上报。
    pub(super) fn contains(&self, assignment_id: i64) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&assignment_id)
    }
}
