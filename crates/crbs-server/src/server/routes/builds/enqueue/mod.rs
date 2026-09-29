// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建入队模块根：执行与提交子模块的导出边界。

mod execute;
mod submit;

pub(crate) use execute::{execute_build, mark_build_failed, reconcile_artifact_registration};
pub(crate) use submit::{
    check_build_chain_visibility, ensure_can_submit_to_product, ensure_no_active_duplicate,
    ensure_shared_result_dir, fan_out_builds, map_noarch_to_concrete, reproduce_fan_out,
    resolve_arches, submit_build, submit_multipart_builds_common, validate_replay_caps,
    validate_replay_caps_by_len, FanOutArgs, FanOutOutcome, ReproduceArchEntry,
    ReproduceFanOutArgs,
};
