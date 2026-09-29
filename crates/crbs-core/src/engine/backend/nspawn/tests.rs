// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You can obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::argv::machine_name_for;
use super::cgroup::{
    resolve_scope_path_in, scope_path_candidates, wait_for_cgroup_procs_or_child_exit,
};
use super::parse::{parse_cpu_quota, parse_memory_max};
use super::*;

fn bind(host: &str, container: &str) -> crate::engine::backend::BindMount {
    crate::engine::backend::BindMount {
        host: host.to_string(),
        container: container.to_string(),
        read_only: false,
    }
}

#[test]
fn test_spawn_argv_basic() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    let opts = SpawnOptions::default();
    let limits = ResourceLimits::default();
    let argv = build_spawn_argv(&rootfs, &["/crbs-build.sh"], &opts, &limits).unwrap();

    assert_eq!(argv[0], "systemd-nspawn");
    assert!(argv.contains(&"--directory=/tmp/rootfs".to_string()));
    assert!(argv.contains(&"--as-pid2".to_string()));
    // 回归（新 systemd）：--register=no 下 machined scope 不创建，进程落回
    // 自身 session cgroup，采样三列 NULL、限制/kill 全失效；必须保持注册（缺省 auto）。
    assert!(!argv.iter().any(|a| a.starts_with("--register")));
    assert!(argv.contains(&"--quiet".to_string()));
    assert!(argv.iter().any(|a| a.starts_with("--capability=cap_")));
    assert!(argv.contains(&"--console=pipe".to_string()));
    assert!(argv.contains(&"--".to_string()));
    assert!(argv.contains(&"/crbs-build.sh".to_string()));
    assert!(!argv.iter().any(|a| a == "--keep-unit"));
    // 不注入 --notify-ready：bash payload 永不 sd_notify，只会等满 30s 超时。
    assert!(!argv.iter().any(|a| a.starts_with("--notify-ready")));
}

#[test]
fn test_spawn_argv_with_env() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    let mut env = BTreeMap::new();
    env.insert("LC_ALL".to_string(), "C".to_string());
    env.insert("RPM_BUILD_NCPUS".to_string(), "8".to_string());
    let opts = SpawnOptions {
        env,
        ..Default::default()
    };
    let limits = ResourceLimits::default();
    let argv = build_spawn_argv(&rootfs, &["/crbs-build.sh"], &opts, &limits).unwrap();

    assert!(argv.contains(&"--setenv=LC_ALL=C".to_string()));
    assert!(argv.contains(&"--setenv=RPM_BUILD_NCPUS=8".to_string()));
    let dash_dash_pos = argv.iter().position(|a| a == "--").unwrap();
    let setenv_pos = argv.iter().position(|a| a == "--setenv=LC_ALL=C").unwrap();
    assert!(setenv_pos < dash_dash_pos);
}

#[test]
fn test_spawn_argv_no_user() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    let opts = SpawnOptions::default();
    let limits = ResourceLimits::default();
    let argv = build_spawn_argv(&rootfs, &["/crbs-build.sh"], &opts, &limits).unwrap();
    assert!(!argv.iter().any(|a| a.starts_with("--user")));
}

#[test]
fn test_spawn_argv_no_keep_unit() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    let opts = SpawnOptions::default();
    let limits = ResourceLimits::default();
    let argv = build_spawn_argv(&rootfs, &["/crbs-build.sh"], &opts, &limits).unwrap();
    assert!(!argv.iter().any(|a| a == "--keep-unit"));
}

#[test]
fn test_spawn_argv_with_limits() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    let opts = SpawnOptions::default();
    let limits = ResourceLimits {
        memory_max: Some("4G".to_string()),
        cpu_quota: Some("200%".to_string()),
    };
    let argv = build_spawn_argv(&rootfs, &["/crbs-build.sh"], &opts, &limits).unwrap();

    // --property= cgroup v1 直接生效，v2 忽略（payload 由 setup_payload_cgroup 处理）
    assert!(argv.contains(&"--property=MemoryMax=4G".to_string()));
    assert!(argv.contains(&"--property=MemoryLimit=4G".to_string()));
    assert!(argv.contains(&"--property=CPUQuota=200%".to_string()));

    let mem_pos = argv
        .iter()
        .position(|a| a == "--property=MemoryMax=4G")
        .unwrap();
    let dash_pos = argv.iter().position(|a| a == "--").unwrap();
    assert!(mem_pos < dash_pos);
}

#[test]
fn test_spawn_argv_cpu_quota_normalized() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    let opts = SpawnOptions::default();

    let limits = ResourceLimits {
        memory_max: None,
        cpu_quota: Some("2".to_string()),
    };
    let argv = build_spawn_argv(&rootfs, &["/crbs-build.sh"], &opts, &limits).unwrap();
    assert!(argv.contains(&"--property=CPUQuota=200%".to_string()));

    let limits = ResourceLimits {
        memory_max: None,
        cpu_quota: Some("50%".to_string()),
    };
    let argv = build_spawn_argv(&rootfs, &["/crbs-build.sh"], &opts, &limits).unwrap();
    assert!(argv.contains(&"--property=CPUQuota=50%".to_string()));
}

/// 未识别的 cpu_quota 在 argv 构造时 fail-fast，不留给 systemd 运行期才失败；
/// cores×100 溢出同样拒绝（非 debug panic）。
#[test]
fn test_spawn_argv_rejects_unrecognized_cpu_quota() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    let opts = SpawnOptions::default();
    let limits = ResourceLimits {
        memory_max: None,
        cpu_quota: Some("2cores".to_string()),
    };
    let err = build_spawn_argv(&rootfs, &["/crbs-build.sh"], &opts, &limits)
        .expect_err("unrecognized cpu_quota must be rejected");
    assert!(matches!(
        err,
        crate::error::CrbsError::ValidationFailed { .. }
    ));

    let limits = ResourceLimits {
        memory_max: None,
        cpu_quota: Some(u64::MAX.to_string()),
    };
    assert!(build_spawn_argv(&rootfs, &["/crbs-build.sh"], &opts, &limits).is_err());
}

#[test]
fn test_spawn_argv_without_limits() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    let opts = SpawnOptions::default();
    let limits = ResourceLimits::default();
    let argv = build_spawn_argv(&rootfs, &["/crbs-build.sh"], &opts, &limits).unwrap();

    assert!(!argv.iter().any(|a| a.starts_with("--property=")));
}

#[test]
fn test_shell_argv_with_user() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    let opts = SpawnOptions {
        user: Some("ccbuilder".to_string()),
        ..Default::default()
    };
    let argv = build_shell_argv(&rootfs, None, &opts).unwrap();

    assert!(argv.contains(&"--user=ccbuilder".to_string()));
    assert!(argv.contains(&"--as-pid2".to_string()));
    assert!(argv.contains(&"--keep-unit".to_string()));
    assert!(argv.contains(&"--console=pipe".to_string()));
    assert!(!argv.contains(&"--console=interactive".to_string()));
    assert!(argv.contains(&"/bin/bash".to_string()));
    assert!(!argv.contains(&"-c".to_string()));
}

#[test]
fn test_shell_argv_console_mode() {
    let rootfs = PathBuf::from("/tmp/rootfs");

    // 有 --user → --console=pipe（规避 systemd 255 SIGKILL bug）
    let opts_user = SpawnOptions {
        user: Some("ccbuilder".to_string()),
        ..Default::default()
    };
    let argv = build_shell_argv(&rootfs, None, &opts_user).unwrap();
    assert!(argv.contains(&"--console=pipe".to_string()));
    assert!(!argv.contains(&"--console=interactive".to_string()));

    let opts_no_user = SpawnOptions::default();
    let argv = build_shell_argv(&rootfs, None, &opts_no_user).unwrap();
    assert!(argv.contains(&"--console=interactive".to_string()));
    assert!(!argv.contains(&"--console=pipe".to_string()));
}

#[test]
fn test_shell_argv_command_vs_interactive() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    let opts = SpawnOptions {
        user: Some("ccbuilder".to_string()),
        ..Default::default()
    };

    let argv = build_shell_argv(&rootfs, Some("whoami"), &opts).unwrap();
    let dash_c_pos = argv.iter().position(|a| a == "-c").unwrap();
    assert_eq!(argv[dash_c_pos + 1], "whoami");

    let argv = build_shell_argv(&rootfs, None, &opts).unwrap();
    assert!(!argv.contains(&"-c".to_string()));
}

#[test]
fn test_shell_argv_with_env() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    let mut env = BTreeMap::new();
    env.insert("FOO".to_string(), "bar".to_string());
    let opts = SpawnOptions {
        env,
        ..Default::default()
    };
    let argv = build_shell_argv(&rootfs, Some("printenv FOO"), &opts).unwrap();
    assert!(argv.contains(&"--setenv=FOO=bar".to_string()));
}

#[test]
fn test_nspawn_backend_name() {
    let backend = NspawnBackend::new();
    assert_eq!(backend.name(), "nspawn");
}

/// 空 command 拒为 ValidationFailed（对齐 chroot backend 边界），不拼出无意义 argv。
#[tokio::test]
async fn test_nspawn_spawn_rejects_empty_command() {
    let backend = NspawnBackend::new();
    let err = backend
        .spawn(
            std::path::Path::new("/tmp/rootfs"),
            &[],
            &SpawnOptions::default(),
        )
        .await
        .err()
        .expect("empty command must be rejected");
    assert!(matches!(
        err,
        crate::error::CrbsError::ValidationFailed { .. }
    ));
}

#[test]
fn test_shell_argv_no_property() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    let opts = SpawnOptions::default();
    let argv = build_shell_argv(&rootfs, Some("whoami"), &opts).unwrap();

    assert!(!argv.iter().any(|a| a.starts_with("--property=")));
}

#[test]
fn test_spawn_argv_network_default() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    let opts = SpawnOptions::default();
    let limits = ResourceLimits::default();
    let argv = build_spawn_argv(&rootfs, &["/crbs-build.sh"], &opts, &limits).unwrap();
    assert!(!argv.iter().any(|a| a == "--private-network"));
}

#[test]
fn test_spawn_argv_private_network() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    let opts = SpawnOptions {
        network: false,
        ..Default::default()
    };
    let limits = ResourceLimits::default();
    let argv = build_spawn_argv(&rootfs, &["/crbs-build.sh"], &opts, &limits).unwrap();
    assert!(argv.contains(&"--private-network".to_string()));
}

#[test]
fn test_shell_argv_private_network() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    let opts = SpawnOptions {
        network: false,
        ..Default::default()
    };
    let argv = build_shell_argv(&rootfs, Some("whoami"), &opts).unwrap();
    assert!(argv.contains(&"--private-network".to_string()));
}

#[test]
fn test_parse_memory_max_bytes() {
    assert_eq!(parse_memory_max("100").unwrap(), 100);
}

#[test]
fn test_parse_memory_max_k() {
    assert_eq!(parse_memory_max("1K").unwrap(), 1024);
}

#[test]
fn test_parse_memory_max_m() {
    assert_eq!(parse_memory_max("1M").unwrap(), 1024 * 1024);
}

#[test]
fn test_parse_memory_max_g() {
    assert_eq!(parse_memory_max("2G").unwrap(), 2 * 1024 * 1024 * 1024);
}

#[test]
fn test_parse_memory_max_zero() {
    assert_eq!(parse_memory_max("0").unwrap(), 0);
}

#[test]
fn test_parse_memory_max_invalid() {
    assert!(parse_memory_max("abc").is_err());
    assert!(parse_memory_max("1.5M").is_err());
}

/// 乘法溢出返回 ValidationFailed 而非 debug panic：2^54×2^40 远超 u64，错误信息带原始输入。
#[test]
fn test_parse_memory_max_overflow_rejected() {
    let cases = ["18014398509481984T", "18446744073709551615K"];
    for c in cases {
        let err = parse_memory_max(c)
            .err()
            .unwrap_or_else(|| panic!("{c} must overflow"));
        assert!(matches!(
            err,
            crate::error::CrbsError::ValidationFailed { .. }
        ));
        assert!(err.to_string().contains(c));
    }
    assert_eq!(
        parse_memory_max("16T").unwrap(),
        16u64 * 1024 * 1024 * 1024 * 1024
    );
}

#[test]
fn test_parse_cpu_quota_percent() {
    assert_eq!(parse_cpu_quota("200%").unwrap(), (200_000, 100_000));
    assert_eq!(parse_cpu_quota("50%").unwrap(), (50_000, 100_000));
}

#[test]
fn test_parse_cpu_quota_cores() {
    assert_eq!(parse_cpu_quota("2").unwrap(), (200_000, 100_000));
    assert_eq!(parse_cpu_quota("1").unwrap(), (100_000, 100_000));
}

#[test]
fn test_parse_cpu_quota_invalid() {
    assert!(parse_cpu_quota("abc").is_err());
    assert!(parse_cpu_quota("200%%").is_err());
}

/// "0" / "0%" 拒绝：cpu.max quota=0 是内核 EINVAL（不是"无限制"）。
#[test]
fn test_parse_cpu_quota_zero_rejected() {
    for c in ["0", "0%"] {
        let err = parse_cpu_quota(c)
            .err()
            .unwrap_or_else(|| panic!("{c} must be rejected"));
        assert!(matches!(
            err,
            crate::error::CrbsError::ValidationFailed { .. }
        ));
    }
}

/// quota×period 溢出返回 ValidationFailed 而非 panic（cores 1e15、percent 1e17% 均越界 u64）。
#[test]
fn test_parse_cpu_quota_overflow_rejected() {
    let err = parse_cpu_quota("1000000000000000").expect_err("cores quota must overflow");
    assert!(matches!(
        err,
        crate::error::CrbsError::ValidationFailed { .. }
    ));
    assert!(parse_cpu_quota("100000000000000000%").is_err());
    assert_eq!(parse_cpu_quota("1024").unwrap(), (102_400_000, 100_000));
}

#[test]
fn test_parse_memory_max_suffix_case_insensitive() {
    // systemd 接受小写后缀（"4g"），解析与之对齐。
    assert_eq!(parse_memory_max("1k").unwrap(), 1024);
    assert_eq!(parse_memory_max("2m").unwrap(), 2 * 1024 * 1024);
    assert_eq!(parse_memory_max("4g").unwrap(), 4 * 1024 * 1024 * 1024);
    assert_eq!(
        parse_memory_max("1t").unwrap(),
        1024u64 * 1024 * 1024 * 1024
    );
}

#[test]
fn test_machine_name_suffix_valid() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    assert!(machine_name_for(&rootfs, Some("42")).is_ok());
    assert!(machine_name_for(&rootfs, Some("build-42")).is_ok());
    assert!(machine_name_for(&rootfs, Some("a.b_c-d")).is_ok());
    // 空≡None（argv 解析侧空串归一为 None）
    assert!(machine_name_for(&rootfs, Some("")).is_ok());
    assert!(machine_name_for(&rootfs, None).is_ok());
    let name = machine_name_for(&rootfs, Some("42")).unwrap();
    assert!(name.starts_with("crbs-"));
    assert!(name.ends_with("-42"));
}

/// machine_name_suffix 白名单校验：拒绝路径分隔符与 `..`（含单独出现）；
/// 该值拼进 machine 名与 cgroup 路径，入口 fail-fast。
#[test]
fn test_machine_name_suffix_rejects_traversal() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    for suffix in ["../evil", "a/b", "a\\b", "..", "a..b", "a b", "a;b", "胜"] {
        let err = machine_name_for(&rootfs, Some(suffix))
            .err()
            .unwrap_or_else(|| panic!("{suffix:?} must be rejected"));
        assert!(
            matches!(err, crate::error::CrbsError::ValidationFailed { .. }),
            "{suffix:?}"
        );
    }
}

/// 坏后缀经 build_spawn_argv / build_shell_argv 同样 fail-fast（入口共用）。
#[test]
fn test_argv_rejects_bad_machine_suffix() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    let opts = SpawnOptions {
        machine_name_suffix: Some("../escape".to_string()),
        ..Default::default()
    };
    assert!(build_spawn_argv(
        &rootfs,
        &["/crbs-build.sh"],
        &opts,
        &ResourceLimits::default()
    )
    .is_err());
    assert!(build_shell_argv(&rootfs, None, &opts).is_err());
}

/// --bind 路径含 ':'（host 或 container 侧）拒绝：--bind 按 ':' 分段且无转义机制。
#[test]
fn test_spawn_argv_rejects_colon_in_bind_path() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    let limits = ResourceLimits::default();

    let opts = SpawnOptions {
        binds: vec![bind("/tmp/a:b", "/mnt/ab")],
        ..Default::default()
    };
    let err = build_spawn_argv(&rootfs, &["/crbs-build.sh"], &opts, &limits);
    assert!(err.is_err());

    let opts = SpawnOptions {
        binds: vec![bind("/tmp/ab", "/mnt/a:b")],
        ..Default::default()
    };
    assert!(build_spawn_argv(&rootfs, &["/crbs-build.sh"], &opts, &limits).is_err());

    let opts = SpawnOptions {
        binds: vec![bind("/data/results", "/mnt/results")],
        ..Default::default()
    };
    let argv = build_spawn_argv(&rootfs, &["/crbs-build.sh"], &opts, &limits).unwrap();
    assert!(argv.contains(&"--bind=/data/results:/mnt/results".to_string()));
}

/// shell argv 同样支持 binds，':' 校验与 spawn 共用；read_only 用 --bind-ro
/// 传递（用户 --bind 默认只读，不得静默降级为 rw）。
#[test]
fn test_shell_argv_supports_binds() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    let opts = SpawnOptions {
        binds: vec![
            bind("/data/src", "/mnt/src"),
            crate::engine::backend::BindMount {
                host: "/data/secret".to_string(),
                container: "/mnt/secret".to_string(),
                read_only: true,
            },
        ],
        ..Default::default()
    };
    let argv = build_shell_argv(&rootfs, Some("whoami"), &opts).unwrap();
    assert!(argv.contains(&"--bind=/data/src:/mnt/src".to_string()));
    assert!(argv.contains(&"--bind-ro=/data/secret:/mnt/secret".to_string()));
    let dash_pos = argv.iter().position(|a| a == "--").unwrap();
    let bind_pos = argv
        .iter()
        .position(|a| a == "--bind=/data/src:/mnt/src")
        .unwrap();
    assert!(bind_pos < dash_pos);

    let opts = SpawnOptions {
        binds: vec![bind("/tmp/a:b", "/mnt/ab")],
        ..Default::default()
    };
    assert!(build_shell_argv(&rootfs, None, &opts).is_err());
}

/// scope 候选必须同时覆盖探测根（v2 统一根 + v1 legacy systemd 根——v1 宿主
/// 层级挂 /sys/fs/cgroup/systemd，缺该前缀探测必落空）、新旧 machined 命名
///（新 `{name}.scope` 无 machine- 前缀，旧 `machine-{name}.scope`）与原样/
/// 转义双形态（machined 注册目录名即 `machine-crbs\x2d…` 转义形态）；只写死
/// 一种必然在另一半宿主上超时。
#[test]
fn test_scope_path_candidates_cover_both_namings() {
    let cands = scope_path_candidates("foo");
    assert_eq!(cands.len(), 8, "2 roots x 4 naming forms");
    // "foo" 无 `-`：转义形态与原样同值，前两条（新式原样/转义）路径一致。
    assert_eq!(cands[0], "/sys/fs/cgroup/machine.slice/foo.scope");
    assert_eq!(cands[1], "/sys/fs/cgroup/machine.slice/foo.scope");
    assert!(cands.contains(&"/sys/fs/cgroup/systemd/machine.slice/foo.scope".to_string()));
    assert!(cands.contains(&"/sys/fs/cgroup/systemd/machine.slice/machine-foo.scope".to_string()));

    let name = machine_name_for(&PathBuf::from("/tmp/rootfs"), Some("build-42")).unwrap();
    let escaped = name.replace('-', "\\x2d");
    let cands = scope_path_candidates(&name);
    assert!(cands.contains(&format!("/sys/fs/cgroup/machine.slice/{name}.scope")));
    assert!(cands.contains(&format!("/sys/fs/cgroup/machine.slice/{escaped}.scope")));
    assert!(cands.contains(&format!(
        "/sys/fs/cgroup/machine.slice/machine-{name}.scope"
    )));
    assert!(cands.contains(&format!(
        "/sys/fs/cgroup/machine.slice/machine-{escaped}.scope"
    )));
    assert!(cands.contains(&format!(
        "/sys/fs/cgroup/systemd/machine.slice/{name}.scope"
    )));
    assert!(cands.contains(&format!(
        "/sys/fs/cgroup/systemd/machine.slice/machine-{escaped}.scope"
    )));
}

#[tokio::test]
async fn test_resolve_scope_prefers_new_naming() {
    let tmp = tempfile::tempdir().unwrap();
    let name = machine_name_for(&PathBuf::from("/tmp/rootfs"), Some("resolve-new")).unwrap();
    tokio::fs::create_dir_all(
        tmp.path()
            .join(format!("machine.slice/{name}.scope/payload")),
    )
    .await
    .unwrap();
    tokio::fs::write(
        tmp.path()
            .join(format!("machine.slice/{name}.scope/payload/cgroup.procs")),
        "1\n",
    )
    .await
    .unwrap();

    let scope = resolve_scope_path_in(tmp.path(), &name)
        .await
        .expect("new-style scope must be found");
    assert!(scope.ends_with(&format!("/{name}.scope")), "{scope}");
}

/// 旧式命名（machine- 前缀）存在 → 回退命中它（旧 systemd 宿主）。
#[tokio::test]
async fn test_resolve_scope_falls_back_to_legacy_naming() {
    let tmp = tempfile::tempdir().unwrap();
    let name = machine_name_for(&PathBuf::from("/tmp/rootfs"), Some("resolve-legacy")).unwrap();
    tokio::fs::create_dir_all(
        tmp.path()
            .join(format!("machine.slice/machine-{name}.scope/payload")),
    )
    .await
    .unwrap();
    tokio::fs::write(
        tmp.path().join(format!(
            "machine.slice/machine-{name}.scope/payload/cgroup.procs"
        )),
        "1\n",
    )
    .await
    .unwrap();

    let scope = resolve_scope_path_in(tmp.path(), &name)
        .await
        .expect("legacy scope must be found");
    assert!(
        scope.ends_with(&format!("/machine-{name}.scope")),
        "{scope}"
    );
}

/// 转义命名（machined 注册的实际目录名形态）存在 → 命中它。
#[tokio::test]
async fn test_resolve_scope_finds_escaped_naming() {
    let tmp = tempfile::tempdir().unwrap();
    let name = machine_name_for(&PathBuf::from("/tmp/rootfs"), Some("resolve-esc")).unwrap();
    let escaped = name.replace('-', "\\x2d");
    tokio::fs::create_dir_all(
        tmp.path()
            .join(format!("machine.slice/machine-{escaped}.scope/payload")),
    )
    .await
    .unwrap();

    let scope = resolve_scope_path_in(tmp.path(), &name)
        .await
        .expect("escaped legacy scope must be found");
    assert!(
        scope.ends_with(&format!("/machine-{escaped}.scope")),
        "{scope}"
    );
}

/// 两种形态都不存在 → None（不放大失败，调用方按等待/兜底推导降级）。
#[tokio::test]
async fn test_resolve_scope_returns_none_when_absent() {
    let tmp = tempfile::tempdir().unwrap();
    let name = machine_name_for(&PathBuf::from("/tmp/rootfs"), Some("resolve-none")).unwrap();
    assert!(resolve_scope_path_in(tmp.path(), &name).await.is_none());
}

#[tokio::test]
async fn test_wait_matches_new_style_candidate() {
    let tmp = tempfile::tempdir().unwrap();
    let name = machine_name_for(&PathBuf::from("/tmp/rootfs"), Some("wait-new")).unwrap();
    let procs_new = tmp
        .path()
        .join(format!("machine.slice/{name}.scope/payload/cgroup.procs"));
    tokio::fs::create_dir_all(procs_new.parent().unwrap())
        .await
        .unwrap();
    tokio::fs::write(&procs_new, "1\n").await.unwrap();
    let procs_paths = [
        procs_new.to_string_lossy().into_owned(),
        tmp.path()
            .join(format!(
                "machine.slice/machine-{name}.scope/payload/cgroup.procs"
            ))
            .to_string_lossy()
            .into_owned(),
    ];

    let mut child = tokio::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let matched =
        wait_for_cgroup_procs_or_child_exit(&procs_paths, Duration::from_secs(5), &mut child)
            .await
            .expect("new-style candidate must be matched");
    assert!(matched.ends_with(&format!("/{name}.scope/payload/cgroup.procs")));
    child.kill().await.unwrap();
}

#[tokio::test]
async fn test_wait_for_cgroup_procs_returns_true_when_file_appears() {
    let tmp = tempfile::tempdir().unwrap();
    let procs = tmp.path().join("cgroup.procs");
    tokio::fs::write(&procs, "1\n").await.unwrap();

    // 子进程保持存活（不触发 wait 分支）。
    let mut child = tokio::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let started = Instant::now();
    let matched = wait_for_cgroup_procs_or_child_exit(
        &[procs.to_string_lossy().into_owned()],
        Duration::from_secs(5),
        &mut child,
    )
    .await;
    assert_eq!(
        matched.as_deref(),
        Some(procs.to_string_lossy().as_ref()),
        "must report the matched candidate path"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    child.kill().await.unwrap();
}

/// 子进程立即退出（如坏 rootfs 启动失败）→ 返回 None 不空等 deadline，构建不被阻塞。
#[tokio::test]
async fn test_wait_returns_immediately_when_child_exits() {
    let mut child = tokio::process::Command::new("true")
        .spawn()
        .expect("spawn true");
    let started = Instant::now();
    let matched = wait_for_cgroup_procs_or_child_exit(
        &["/nonexistent/crbs/test/cgroup.procs".to_string()],
        Duration::from_secs(10),
        &mut child,
    )
    .await;
    assert!(matched.is_none());
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "must not wait the full deadline when the child already exited"
    );

    // 已收尸后再 wait 幂等返回缓存状态（run_script_phase spawn 后还会 wait）。
    let status = child.wait().await.unwrap();
    assert!(status.success());
}

/// 候选 procs 不出现且子进程存活 → deadline 到期返回 None（测试 100ms，生产 10s）。
#[tokio::test]
async fn test_wait_times_out_when_neither_happens() {
    let mut child = tokio::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let started = Instant::now();
    let matched = wait_for_cgroup_procs_or_child_exit(
        &[
            "/nonexistent/crbs/test/a/cgroup.procs".to_string(),
            "/nonexistent/crbs/test/b/cgroup.procs".to_string(),
        ],
        Duration::from_millis(100),
        &mut child,
    )
    .await;
    assert!(matched.is_none());
    assert!(started.elapsed() < Duration::from_secs(5));
    child.kill().await.unwrap();
}

/// hostname 钉死：Some → `--hostname=crbs-build`，None 不带；shell argv
/// 不注入（交互 shell 保持宿主语义）。
#[test]
fn test_spawn_argv_hostname_pin() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    let opts = SpawnOptions {
        hostname: Some("crbs-build".to_string()),
        ..Default::default()
    };
    let argv = build_spawn_argv(
        &rootfs,
        &["/crbs-build.sh"],
        &opts,
        &ResourceLimits::default(),
    )
    .unwrap();
    assert!(argv.contains(&"--hostname=crbs-build".to_string()));

    let plain = build_spawn_argv(
        &rootfs,
        &["/crbs-build.sh"],
        &SpawnOptions::default(),
        &ResourceLimits::default(),
    )
    .unwrap();
    assert!(!plain.iter().any(|a| a.starts_with("--hostname")));
}

/// 非 det 源构建的 worker 主机名钉值（decide_container_hostname 产出侧）：值
/// 原样进 `--hostname=`（priv-helper 字符集白名单同口径校验已在
/// phase::hostname_value_valid 前置，argv 层只负责透传）。
#[test]
fn test_spawn_argv_hostname_worker_value_passthrough() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    let opts = SpawnOptions {
        hostname: Some("CUBS-A64".to_string()),
        ..Default::default()
    };
    let argv = build_spawn_argv(
        &rootfs,
        &["/crbs-build.sh"],
        &opts,
        &ResourceLimits::default(),
    )
    .unwrap();
    assert!(argv.contains(&"--hostname=CUBS-A64".to_string()));
}

/// 回归：deterministic env 基线（build_spawn_env(true)）经 SpawnOptions.env
/// 每键一条 `--setenv=K=V`，与 chroot 共享同一注入（护栏测试在 backend/mod.rs）。
#[test]
fn test_spawn_argv_carries_full_deterministic_env_baseline() {
    let rootfs = PathBuf::from("/tmp/rootfs");
    let env = crate::engine::build::phase::build_spawn_env(true, None);
    let opts = SpawnOptions {
        env,
        ..Default::default()
    };
    let argv = build_spawn_argv(
        &rootfs,
        &["/crbs-build.sh"],
        &opts,
        &ResourceLimits::default(),
    )
    .unwrap();
    for (k, v) in [
        ("LC_ALL", "C"),
        ("TZ", "UTC"),
        ("PYTHONHASHSEED", "0"),
        ("PERL_HASH_SEED", "0"),
        ("PERL_PERTURB_KEYS", "0"),
    ] {
        assert!(
            argv.contains(&format!("--setenv={k}={v}")),
            "missing --setenv={k}={v} in {argv:?}"
        );
    }
}
