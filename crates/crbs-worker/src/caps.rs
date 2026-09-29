// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 节点采集能力探测与上报侧附加量：启动探测能力位图（注册/心跳携带）、终态上报
//! 附带的执行节点核数。
//! 探测的务实规则：文件存在即认为有能力（cgroup v2 统一层级以 cgroup.controllers
//! 为准；memory.peak / memory.events / io.stat 按根 cgroup 下的文件判位；PSI 按
//! /proc/pressure 任一文件判位）。探测失败或文件缺失 = 位清零（降级安全），绝不
//! 影响 worker 启动。

use std::path::Path;

use crbs_core::{
    RESOURCE_CAP_CGROUP_V2, RESOURCE_CAP_IO_STAT, RESOURCE_CAP_MEMORY_EVENTS,
    RESOURCE_CAP_MEMORY_PEAK, RESOURCE_CAP_PSI,
};

/// 探测节点采集能力位图（位定义见 state 层 RESOURCE_CAP_* 常量）。cgroup_root 生产
/// 传 /sys/fs/cgroup、proc_root 传 /proc，参数化以便注入文件树测试。memory.peak /
/// memory.events / io.stat 只在 v2 统一层级的根 cgroup 出现（v1 控制器分层挂载，
/// 天然自行排除）。
pub fn probe_resource_caps(cgroup_root: &Path, proc_root: &Path) -> i64 {
    let mut caps = 0i64;
    if cgroup_root.join("cgroup.controllers").exists() {
        caps |= RESOURCE_CAP_CGROUP_V2;
    }

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

pub fn probe_resource_caps_default() -> i64 {
    probe_resource_caps(Path::new("/sys/fs/cgroup"), Path::new("/proc"))
}

/// 执行节点逻辑核数（与心跳 ncpu 同源 available_parallelism）；取不到返回 None
/// （上报层据此不附加 sample_ncpu，落库 NULL）。
pub fn worker_ncpu() -> Option<i64> {
    std::thread::available_parallelism()
        .ok()
        .map(|v| v.get() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn probe_caps_full_and_degrades_per_bit() {
        let tmp = tempfile::tempdir().unwrap();
        let cgroup = tmp.path().join("cgroup");
        let proc = tmp.path().join("proc");
        fs::create_dir_all(&cgroup).unwrap();
        fs::create_dir_all(proc.join("pressure")).unwrap();

        assert_eq!(probe_resource_caps(&cgroup, &proc), 0);

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

        let cpu_only = tmp.path().join("proc-cpu-only");
        fs::create_dir_all(cpu_only.join("pressure")).unwrap();
        fs::write(cpu_only.join("pressure").join("cpu"), b"").unwrap();
        assert_eq!(
            probe_resource_caps(&v1_host, &cpu_only),
            RESOURCE_CAP_PSI,
            "any pressure file counts"
        );

        assert_eq!(
            probe_resource_caps(Path::new("/nonexistent-a"), Path::new("/nonexistent-b")),
            0
        );
    }

    #[test]
    fn worker_ncpu_positive() {
        let n = worker_ncpu().expect("available_parallelism must work in tests");
        assert!(n >= 1);
    }
}
