// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 节点采集能力探测与上报侧附加量：启动探测能力位图（注册/心跳携带）、
//! 终态上报附带的执行节点核数。
//!
//! 探测务实口径：文件存在性即能力（cgroup v2 统一层级以
//! `cgroup.controllers` 为准；memory.peak / memory.events / io.stat 按根
//! cgroup 下文件存在判位；PSI 按 `/proc/pressure` 任一文件判位）。探测
//! 失败 / 文件缺失 = 位清零（降级安全），绝不影响 worker 启动。

use std::path::Path;

use crbs_core::{
    RESOURCE_CAP_CGROUP_V2, RESOURCE_CAP_IO_STAT, RESOURCE_CAP_MEMORY_EVENTS,
    RESOURCE_CAP_MEMORY_PEAK, RESOURCE_CAP_PSI,
};

/// 探测节点采集能力位图（位定义见 state 层 `RESOURCE_CAP_*` 常量）。
/// `cgroup_root` 生产传 `/sys/fs/cgroup`、`proc_root` 传 `/proc`，参数化供
/// 文件树 fixture 注入测试。任一位探测失败按清零处理（降级安全）。
pub fn probe_resource_caps(cgroup_root: &Path, proc_root: &Path) -> i64 {
    let mut caps = 0i64;
    if cgroup_root.join("cgroup.controllers").exists() {
        caps |= RESOURCE_CAP_CGROUP_V2;
    }
    // memory.peak / memory.events / io.stat 只在 v2 统一层级的根 cgroup 出现
    //（v1 控制器分层挂载，天然自门控），不做 v2 位的前置与。
    if cgroup_root.join("memory.peak").exists() {
        caps |= RESOURCE_CAP_MEMORY_PEAK;
    }
    if cgroup_root.join("memory.events").exists() {
        caps |= RESOURCE_CAP_MEMORY_EVENTS;
    }
    if cgroup_root.join("io.stat").exists() {
        caps |= RESOURCE_CAP_IO_STAT;
    }
    if ["cpu", "memory", "io"]
        .iter()
        .any(|f| proc_root.join("pressure").join(f).exists())
    {
        caps |= RESOURCE_CAP_PSI;
    }
    caps
}

/// 生产路径探测（默认根路径）；供启动流程经 spawn_blocking 调用。
pub fn probe_resource_caps_default() -> i64 {
    probe_resource_caps(Path::new("/sys/fs/cgroup"), Path::new("/proc"))
}

/// 执行节点逻辑核数（与心跳 ncpu 同源 available_parallelism）；取不到返回
/// `None`（上报层据此不附加 sample_ncpu，落库 NULL）。
pub fn worker_ncpu() -> Option<i64> {
    std::thread::available_parallelism()
        .ok()
        .map(|v| v.get() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// 全能力文件树 → 五位全亮；逐位缺失 → 对应位清零（降级安全）。
    #[test]
    fn probe_caps_full_and_degrades_per_bit() {
        let tmp = tempfile::tempdir().unwrap();
        let cgroup = tmp.path().join("cgroup");
        let proc = tmp.path().join("proc");
        fs::create_dir_all(&cgroup).unwrap();
        fs::create_dir_all(proc.join("pressure")).unwrap();

        // 空文件树：全零。
        assert_eq!(probe_resource_caps(&cgroup, &proc), 0);

        // v2 + 三控制文件 + PSI 任一 → 全位。
        fs::write(cgroup.join("cgroup.controllers"), b"").unwrap();
        fs::write(cgroup.join("memory.peak"), b"").unwrap();
        fs::write(cgroup.join("memory.events"), b"").unwrap();
        fs::write(cgroup.join("io.stat"), b"").unwrap();
        fs::write(proc.join("pressure").join("memory"), b"").unwrap();
        let full = probe_resource_caps(&cgroup, &proc);
        assert_eq!(
            full,
            RESOURCE_CAP_CGROUP_V2
                | RESOURCE_CAP_MEMORY_PEAK
                | RESOURCE_CAP_MEMORY_EVENTS
                | RESOURCE_CAP_IO_STAT
                | RESOURCE_CAP_PSI
        );

        // 逐位缺失：v1 宿主（无 cgroup.controllers，也无 v2 控制文件）只剩
        // PSI；PSI 缺失只剩 cgroup 位。
        let v1_host = tmp.path().join("v1");
        fs::create_dir_all(&v1_host).unwrap();
        assert_eq!(probe_resource_caps(&v1_host, &proc), RESOURCE_CAP_PSI);
        let no_psi = tmp.path().join("nopressure-proc");
        fs::create_dir_all(&no_psi).unwrap();
        assert_eq!(
            probe_resource_caps(&cgroup, &no_psi),
            RESOURCE_CAP_CGROUP_V2
                | RESOURCE_CAP_MEMORY_PEAK
                | RESOURCE_CAP_MEMORY_EVENTS
                | RESOURCE_CAP_IO_STAT
        );

        // PSI 任一文件存在即判位（cpu 单独存在足够）。
        let cpu_only = tmp.path().join("proc-cpu-only");
        fs::create_dir_all(cpu_only.join("pressure")).unwrap();
        fs::write(cpu_only.join("pressure").join("cpu"), b"").unwrap();
        assert_eq!(
            probe_resource_caps(&v1_host, &cpu_only),
            RESOURCE_CAP_PSI,
            "any pressure file counts"
        );

        // 目录不存在（非 Linux / 探测失败）：全零不 panic。
        assert_eq!(
            probe_resource_caps(Path::new("/nonexistent-a"), Path::new("/nonexistent-b")),
            0
        );
    }

    /// worker_ncpu 返回正核数（available_parallelism 在测试环境恒可用）。
    #[test]
    fn worker_ncpu_positive() {
        let n = worker_ncpu().expect("available_parallelism must work in tests");
        assert!(n >= 1);
    }
}
