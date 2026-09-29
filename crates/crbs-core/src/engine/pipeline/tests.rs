// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use crate::config::Hooks;
use crate::engine::pipeline::patch::generate_patch_bash;
use crate::engine::pipeline::{hook_files, Pipeline, StepContext};

fn make_ctx(hooks: &Hooks) -> StepContext<'_> {
    StepContext {
        builder_user: "builder",
        build_target: "bb",
        rpm_macros: &[],
        srpm_name: "test-1.0-1.fc42.src.rpm",
        ccache_enabled: false,
        ccache_max_size: "10G",
        dnf_cache_enabled: false,
        has_shared_layer: false,
        hooks,
        nocheck: false,
        noclean: false,
        nodebuginfo: false,
        target_arch: None,
        local_repo_dir: None,
        follow_logs: false,
        deterministic: false,
        ccache_cold: false,
        builddep_install_weak_deps: true,
        source_date_epoch: None,
        replay_snapshot_domain: false,
    }
}

#[test]
fn compose_produces_valid_script_header() {
    let hooks = Hooks::default();
    let ctx = make_ctx(&hooks);
    let pipeline = Pipeline::rpm_build();
    let script = pipeline.compose(&ctx);
    assert!(script.starts_with("#!/bin/bash\n"));
    assert!(script.contains("set -e\n"));
    assert!(script.contains("set -o pipefail\n"));
    assert!(script.contains("export LC_ALL=C\n"));
    assert!(script.contains("export TERM=dumb\n"));
}

#[test]
fn compose_contains_all_steps() {
    let hooks = Hooks::default();
    let ctx = make_ctx(&hooks);
    let pipeline = Pipeline::rpm_build();
    let script = pipeline.compose(&ctx);
    assert!(script.contains("# [step:ccache-init]"));
    assert!(script.contains("# [step:install-srpm]"));
    assert!(script.contains("# [step:install-deps]"));
    assert!(script.contains("# [step:build]"));
    assert!(script.contains("# [step:ccache-summary]"));
}

#[test]
fn compose_disables_step() {
    let hooks = Hooks::default();
    let ctx = make_ctx(&hooks);
    let pipeline = Pipeline::rpm_build().disable("ccache-init");
    let script = pipeline.compose(&ctx);
    assert!(!script.contains("# [step:ccache-init]"));
    assert!(script.contains("# [step:install-srpm]"));
}

#[test]
fn compose_shared_layer_skips_deps() {
    let hooks = Hooks::default();
    let ctx = StepContext {
        has_shared_layer: true,
        ..make_ctx(&hooks)
    };
    let pipeline = Pipeline::rpm_build();
    let script = pipeline.compose(&ctx);
    assert!(script.contains("# [step:install-deps]"));
    assert!(!script.contains("dnf builddep"));
}

/// install-srpm / install-deps 输出进 build.log（Rust 侧流式捕获），不 tee 到 root.log。
#[test]
fn compose_install_steps_stream_to_build_log() {
    let hooks = Hooks::default();
    let ctx = make_ctx(&hooks);
    let pipeline = Pipeline::rpm_build();
    let script = pipeline.compose(&ctx);
    assert!(
        script.contains("rpm -Uvh --define \"_topdir /builddir\" /builddir/INPUT/'test-1.0-1.fc42.src.rpm' 2>&1\n"),
        "install-srpm output must stay on stdout for build.log capture"
    );
    assert!(
        script.contains(
            "dnf builddep -y --refresh --setopt=keepcache=True /builddir/SPECS/*.spec 2>&1\n"
        ),
        "install-deps output must stay on stdout for build.log capture"
    );
    assert!(!script.contains("root.log"));
}

#[test]
fn compose_with_ccache() {
    let hooks = Hooks::default();
    let ctx = StepContext {
        ccache_enabled: true,
        ccache_max_size: "5G",
        ..make_ctx(&hooks)
    };
    let pipeline = Pipeline::rpm_build();
    let script = pipeline.compose(&ctx);
    assert!(script.contains("ccache -M '5G'"));
    assert!(script.contains("CCACHE_DIR=/var/cache/ccache-crbs"));
    assert!(script.contains("ccache -s"));
}

/// ccache 双步骤 best-effort：ccache 缺失时不得有被 set -e 杀死的裸调用——每条含 `ccache -` 的行须有 `||` 兜底或为 command -v 守卫自身。
#[test]
fn compose_ccache_steps_are_best_effort() {
    let hooks = Hooks::default();
    let ctx = StepContext {
        ccache_enabled: true,
        ccache_max_size: "5G",
        ..make_ctx(&hooks)
    };
    let script = Pipeline::rpm_build().compose(&ctx);
    assert!(
        script.contains(
            "export PATH=/usr/lib64/ccache:$PATH\nif command -v ccache >/dev/null 2>&1; then"
        ),
        "ccache-init must export PATH then guard with command -v: {script}"
    );
    assert!(
        script.contains("if PATH=/usr/lib64/ccache:$PATH command -v ccache >/dev/null 2>&1; then"),
        "ccache-summary must guard with PATH-prefixed command -v: {script}"
    );
    let warn = "echo \"warning: ccache not active, building without cache\" >&2";
    assert!(
        script.contains(&format!("ccache -M '5G' || {warn}")),
        "ccache -M must have warning fallback: {script}"
    );
    assert!(
        script.contains(&format!("ccache -z || {warn}")),
        "ccache -z must have warning fallback: {script}"
    );
    assert!(
        script.contains("ccache -s || true"),
        "ccache -s must have silent fallback: {script}"
    );
    for line in script.lines().filter(|l| l.contains("ccache -")) {
        let trimmed = line.trim_end();
        let is_guard = trimmed.contains("command -v ccache");
        let has_fallback = trimmed.ends_with("|| true") || trimmed.ends_with(&format!("|| {warn}"));
        assert!(
            is_guard || has_fallback,
            "unguarded ccache invocation would be killed by set -e: {line}"
        );
    }
}

/// reproduce/provenance 依赖 compose 输出逐字节确定（宏序列、hook 注入不得随机）。
#[test]
fn compose_twice_is_byte_identical() {
    let mut hooks = Hooks::default();
    hooks
        .pre
        .insert("install-deps".to_string(), "echo 'pre-deps'\n".to_string());
    hooks
        .post
        .insert("ccache-init".to_string(), "echo 'post-init'\n".to_string());
    let ctx = StepContext {
        rpm_macros: &[("dist".to_string(), ".fc42".to_string())],
        ..make_ctx(&hooks)
    };
    let pipeline = Pipeline::rpm_build();
    assert_eq!(pipeline.compose(&ctx), pipeline.compose(&ctx));
}

#[test]
fn compose_with_rpm_macros() {
    let hooks = Hooks::default();
    let ctx = StepContext {
        rpm_macros: &[
            ("_topdir".to_string(), "/builddir".to_string()),
            ("_smp_mflags".to_string(), "-j4".to_string()),
            // 宏值带空格/单引号：shell_quote 须整体单引号包裹且 '\'' 转义，否则 rpmbuild 收到被拆开的 argv。
            ("vendor".to_string(), "Acme Corp".to_string()),
            ("packager".to_string(), "John O'Brien <john@x>".to_string()),
        ],
        ..make_ctx(&hooks)
    };
    let pipeline = Pipeline::rpm_build();
    let script = pipeline.compose(&ctx);
    assert!(script.contains("--define '_topdir /builddir'"));
    assert!(script.contains("--define '_smp_mflags -j4'"));
    assert!(script.contains("--define 'vendor Acme Corp'"));
    assert!(
        script.contains("--define 'packager John O'\\''Brien <john@x>'"),
        "single quote in macro value must render as '\\'' via shell_quote: {script}"
    );
}

/// install-post 挂载点恒注入且排在用户宏之前（后置 --define 覆盖口子保留）：
/// `crbs_normalize_payload` 未定义时条件段为空、展开与发行版原 brp 宏定义
/// 一致，对既有构建零行为变更；定义时其宏体紧跟 brp-strip-static-archive
/// 之后执行（挂载点谓词见 rpmbuild_bash 的 INSTALL_POST_HOOK_DEFINE 注）。
#[test]
fn compose_mounts_normalize_hook_in_install_post_chain() {
    let hooks = Hooks::default();
    let ctx = StepContext {
        rpm_macros: &[("_topdir".to_string(), "/builddir".to_string())],
        ..make_ctx(&hooks)
    };
    let script = Pipeline::rpm_build().compose(&ctx);

    let shim_line = concat!(
        "--define '__brp_strip_static_archive %{_rpmconfigdir}/brp-strip-static-archive ",
        "%{__strip}%{?crbs_normalize_payload:\n    %{crbs_normalize_payload}}'"
    );
    assert!(
        script.contains(shim_line),
        "install-post mount define must be present verbatim: {script}"
    );
    let shim_pos = script.find(shim_line).unwrap();
    let user_pos = script.find("--define '_topdir /builddir'").unwrap();
    assert!(
        shim_pos < user_pos,
        "mount define must precede user macros so later --define can override"
    );
}

#[test]
fn compose_with_dnf_cache() {
    let hooks = Hooks::default();
    let ctx = StepContext {
        dnf_cache_enabled: true,
        ..make_ctx(&hooks)
    };
    let pipeline = Pipeline::rpm_build();
    let script = pipeline.compose(&ctx);
    assert!(script.contains("--setopt=cachedir=/var/cache/dnf"));
}

#[test]
fn compose_install_deps_forces_metadata_refresh() {
    let hooks = Hooks::default();
    let ctx = make_ctx(&hooks);
    let pipeline = Pipeline::rpm_build();
    let script = pipeline.compose(&ctx);
    // --refresh 强制回源校验 repo 元数据：防 keepcache 持久化的 repodata 在 metadata_expire 窗口内屏蔽上游更新。
    assert!(script.contains("dnf builddep -y --refresh"));
}

/// 默认（builddep_install_weak_deps=true 为省略归一值）脚本不带 install_weak_deps setopt——保持 dnf 默认（装 weak deps），存量产品脚本逐字节不变。
#[test]
fn compose_install_deps_default_keeps_weak_deps() {
    let hooks = Hooks::default();
    let ctx = make_ctx(&hooks);
    let script = Pipeline::rpm_build().compose(&ctx);
    assert!(
        !script.contains("install_weak_deps"),
        "default must keep dnf weak-deps behavior: {script}"
    );
}

/// builddep_install_weak_deps=false：builddep 追加 --setopt=install_weak_deps=False（弱依赖启发式收窄，降低构建环境方差）。
#[test]
fn compose_install_deps_weak_deps_disabled_adds_setopt() {
    let hooks = Hooks::default();
    let ctx = StepContext {
        builddep_install_weak_deps: false,
        ..make_ctx(&hooks)
    };
    let script = Pipeline::rpm_build().compose(&ctx);
    assert!(
        script.contains(
            "dnf builddep -y --refresh --setopt=keepcache=True --setopt=install_weak_deps=False /builddir/SPECS/*.spec 2>&1\n"
        ),
        "weak-deps-off must append the setopt to the builddep line: {script}"
    );
}

/// weak-deps off 与 dnf_cache / local_repo 组合：全部选项落在同一条 builddep 命令上，互不挤掉。
#[test]
fn compose_install_deps_weak_deps_off_combines_with_cache_and_local_repo() {
    let hooks = Hooks::default();
    let ctx = StepContext {
        dnf_cache_enabled: true,
        local_repo_dir: Some("/mnt/crbs-repo"),
        builddep_install_weak_deps: false,
        ..make_ctx(&hooks)
    };
    let script = Pipeline::rpm_build().compose(&ctx);
    let line = script
        .lines()
        .find(|l| l.contains("dnf builddep"))
        .unwrap_or_else(|| panic!("no builddep line: {script}"));
    assert!(line.contains("--setopt=cachedir=/var/cache/dnf"));
    assert!(line.contains("--enablerepo=crbs-local"));
    assert!(line.contains("--setopt=keepcache=True"));
    assert!(line.contains("--setopt=install_weak_deps=False"));
}

/// replay 密闭：builddep 追加 --disablerepo=*，crbs-local（记录全集仓）成
/// 唯一源——dnf5<5.1 无 repo priority，唯一源与 dnf 版本无关。
#[test]
fn compose_install_deps_replay_disables_all_but_local_repo() {
    let hooks = Hooks::default();
    let ctx = StepContext {
        local_repo_dir: Some("/mnt/crbs-repo"),
        replay_snapshot_domain: true,
        ..make_ctx(&hooks)
    };
    let script = Pipeline::rpm_build().compose(&ctx);
    let line = script
        .lines()
        .find(|l| l.contains("dnf builddep"))
        .unwrap_or_else(|| panic!("no builddep line: {script}"));
    assert!(
        line.contains("--disablerepo=* --enablerepo=crbs-local"),
        "replay install-deps must pin crbs-local as the only repo: {line}"
    );
}

#[test]
fn compose_injects_phase_timing_markers() {
    let hooks = Hooks::default();
    let ctx = make_ctx(&hooks);
    let script = Pipeline::rpm_build().compose(&ctx);
    // make_ctx 未启用 ccache，故 init 输出 SKIP。
    assert!(script.contains("CRBS_PHASE_SKIP ccache-init"));
    assert!(script.contains("CRBS_PHASE_START install-srpm"));
    assert!(script.contains("CRBS_PHASE_END install-srpm"));
    assert!(script.contains("CRBS_PHASE_START install-deps"));
    assert!(script.contains("CRBS_PHASE_END install-deps"));
    assert!(script.contains("CRBS_PHASE_START build"));
    assert!(script.contains("CRBS_PHASE_END build"));
}

#[test]
fn compose_shared_layer_emits_skip_marker_for_empty_deps() {
    let hooks = Hooks::default();
    let ctx = StepContext {
        has_shared_layer: true,
        ..make_ctx(&hooks)
    };
    let script = Pipeline::rpm_build().compose(&ctx);
    assert!(script.contains("CRBS_PHASE_SKIP install-deps shared_layer"));
}

/// 步骤体为空（步骤被跳过）时 hooks 围绕 SKIP 标记注入，而非被静默丢弃。
#[test]
fn compose_emits_hooks_around_skip_marker() {
    let mut hooks = Hooks::default();
    hooks
        .pre
        .insert("install-deps".to_string(), "echo 'pre-deps'\n".to_string());
    hooks
        .post
        .insert("install-deps".to_string(), "echo 'post-deps'\n".to_string());
    let ctx = StepContext {
        has_shared_layer: true,
        ..make_ctx(&hooks)
    };
    let script = Pipeline::rpm_build().compose(&ctx);
    let skip_idx = script.find("CRBS_PHASE_SKIP install-deps").unwrap();
    let pre_idx = script.find(". /crbs-hooks/pre-install-deps.sh\n").unwrap();
    let post_idx = script.find(". /crbs-hooks/post-install-deps.sh\n").unwrap();
    assert!(
        pre_idx < skip_idx && skip_idx < post_idx,
        "hooks must wrap the SKIP marker in pre/post order: {script}"
    );
    // hook 体不进脚本：脚本对容器内全体可读，hook 体只允许存在于受限的 /crbs-hooks 文件（0640 builder 属主）。
    assert!(
        !script.contains("pre-deps") && !script.contains("post-deps"),
        "hook bodies must not appear in the script: {script}"
    );
}

#[test]
fn compose_with_hooks() {
    let mut hooks = Hooks::default();
    hooks.pre.insert(
        "install-srpm".to_string(),
        "echo 'pre-install hook'\n".to_string(),
    );
    hooks
        .post
        .insert("build".to_string(), "echo 'post-build hook'\n".to_string());
    let ctx = make_ctx(&hooks);
    let pipeline = Pipeline::rpm_build();
    let script = pipeline.compose(&ctx);
    // 引用形态：source 固定路径（同 shell 执行，export 与 set -e 语义不变）。
    assert!(script.contains("# [hook:pre-install-srpm]\n. /crbs-hooks/pre-install-srpm.sh\n"));
    assert!(script.contains("# [hook:post-build]\n. /crbs-hooks/post-build.sh\n"));
    assert!(
        !script.contains("pre-install hook") && !script.contains("post-build hook"),
        "hook bodies must not appear in the script: {script}"
    );
}

/// hook 文件枚举与脚本引用一一对应：固定路径、内容为 hook 体（保尾换行）；只覆盖脚本可引用的步骤/段名——未知步骤名不落文件（与脚本侧忽略口径一致）。
#[test]
fn hook_files_match_script_references() {
    let mut hooks = Hooks::default();
    hooks.pre.insert(
        "install-srpm".to_string(),
        "echo 'pre-install hook'\n".to_string(),
    );
    hooks
        .spec_post
        .insert("check".to_string(), "echo 'spec hook'".to_string());
    hooks
        .pre
        .insert("not-a-step".to_string(), "echo 'orphan'\n".to_string());
    let ctx = make_ctx(&hooks);

    let files = hook_files(&ctx);
    let mut by_path: std::collections::BTreeMap<String, String> = files
        .into_iter()
        .map(|f| (f.container_path, f.content))
        .collect();
    assert_eq!(
        by_path.remove("/crbs-hooks/pre-install-srpm.sh").unwrap(),
        "echo 'pre-install hook'\n"
    );
    // 无尾换行的 hook 体补齐换行。
    assert_eq!(
        by_path.remove("/crbs-hooks/spec-post-check.sh").unwrap(),
        "echo 'spec hook'\n"
    );
    assert!(by_path.is_empty(), "orphan hooks must not produce files");

    let script = Pipeline::rpm_build().compose(&ctx);
    for line in script.lines() {
        if let Some(path) = line.strip_prefix(". /crbs-hooks/") {
            let full = format!("/crbs-hooks/{path}");
            assert!(
                hook_files(&ctx).iter().any(|f| f.container_path == full),
                "script references {full} but hook_files does not provide it"
            );
        }
    }
}

#[test]
fn compose_with_nocheck() {
    let hooks = Hooks::default();
    let ctx = StepContext {
        nocheck: true,
        ..make_ctx(&hooks)
    };
    let script = Pipeline::rpm_build().compose(&ctx);
    assert!(script.contains("--nocheck"));
}

#[test]
fn compose_with_nodebuginfo() {
    let hooks = Hooks::default();
    let ctx = StepContext {
        nodebuginfo: true,
        ..make_ctx(&hooks)
    };
    let script = Pipeline::rpm_build().compose(&ctx);
    assert!(script.contains("--nodebuginfo"));
}

/// --noclean 开关注入：置位时进命令行（跳过 distro 收尾清理段 %clean/rmbuild——
/// 一次性 overlay 里 BUILD 树回收归引擎 teardown，清理段与产物零关系且对
/// 非 root builder 是失败源），默认关时不出现在命令行上。
#[test]
fn compose_noclean_flag_gating() {
    let hooks = Hooks::default();
    let ctx = StepContext {
        noclean: true,
        ..make_ctx(&hooks)
    };
    let script = Pipeline::rpm_build().compose(&ctx);
    assert!(script.contains("--noclean"), "{script}");

    let script = Pipeline::rpm_build().compose(&make_ctx(&hooks));
    assert!(
        !script.contains("--noclean"),
        "default must not inject: {script}"
    );
}

#[test]
fn compose_with_target_arch() {
    let hooks = Hooks::default();
    let ctx = StepContext {
        target_arch: Some("x86_64_v3"),
        ..make_ctx(&hooks)
    };
    let script = Pipeline::rpm_build().compose(&ctx);
    assert!(script.contains("--target 'x86_64_v3'"));
}

/// follow-logs 时 phase 标记只写 stdout：stream_build_log 把 stdout 逐行持久化进 build.log，脚本内 tee -a 会双写（SKIP 不幂等，会在 profile.json 重复）。
#[test]
fn compose_with_follow_logs_emits_markers_to_stdout_only() {
    let hooks = Hooks::default();
    let ctx = StepContext {
        follow_logs: true,
        ..make_ctx(&hooks)
    };
    let script = Pipeline::rpm_build().compose(&ctx);
    assert!(
        script.contains("CRBS_PHASE_SKIP ccache-init")
            && script.contains("CRBS_PHASE_START install-srpm")
            && script.contains("CRBS_PHASE_END build"),
        "phase markers must still be emitted under follow-logs: {script}"
    );
    assert!(
        !script.contains("tee -a /builddir/result/build.log")
            && !script.contains(">> /builddir/result/build.log"),
        "markers must not be redirected/tee'd into build.log by the script itself: {script}"
    );
}

#[test]
fn compose_without_follow_logs_redirects_phase_markers() {
    let hooks = Hooks::default();
    let ctx = make_ctx(&hooks);
    let script = Pipeline::rpm_build().compose(&ctx);
    assert!(
        script.contains("CRBS_PHASE_START install-srpm")
            && script.contains(">> /builddir/result/build.log"),
        "default should redirect phase markers to build.log only: {script}"
    );
}

#[test]
fn reproduce_phase1_deps_only() {
    let hooks = Hooks::default();
    let ctx = make_ctx(&hooks);
    let script = Pipeline::rpm_build()
        .disable("build")
        .disable("ccache-summary")
        .compose(&ctx);
    assert!(script.contains("# [step:ccache-init]"));
    assert!(script.contains("# [step:install-srpm]"));
    assert!(script.contains("# [step:install-deps]"));
    assert!(!script.contains("# [step:build]"));
    assert!(!script.contains("# [step:ccache-summary]"));
}

#[test]
fn reproduce_phase2_build_only() {
    let hooks = Hooks::default();
    let ctx = make_ctx(&hooks);
    let script = Pipeline::rpm_build()
        .disable("ccache-init")
        .disable("install-srpm")
        .disable("install-deps")
        .compose(&ctx);
    assert!(!script.contains("# [step:ccache-init]"));
    assert!(!script.contains("# [step:install-srpm]"));
    assert!(!script.contains("# [step:install-deps]"));
    assert!(script.contains("# [step:build]"));
    assert!(script.contains("# [step:ccache-summary]"));
}

#[test]
fn reproduce_phases_cover_all_steps() {
    let hooks = Hooks::default();
    let ctx = make_ctx(&hooks);
    let p1 = Pipeline::rpm_build()
        .disable("build")
        .disable("ccache-summary")
        .compose(&ctx);
    let p2 = Pipeline::rpm_build()
        .disable("ccache-init")
        .disable("install-srpm")
        .disable("install-deps")
        .compose(&ctx);
    let full = Pipeline::rpm_build().compose(&ctx);
    for step in &[
        "ccache-init",
        "install-srpm",
        "install-deps",
        "build",
        "ccache-summary",
    ] {
        let tag = format!("# [step:{}]", step);
        assert!(full.contains(&tag), "full script missing {}", step);
        assert!(
            p1.contains(&tag) || p2.contains(&tag),
            "phase scripts missing {}",
            step
        );
        assert!(
            !(p1.contains(&tag) && p2.contains(&tag)),
            "step {} appears in both phases",
            step
        );
    }
}

fn run_patch_bash(ctx: &StepContext, spec: &str) -> String {
    let bash = generate_patch_bash(ctx);
    let tmp = tempfile::tempdir().unwrap();
    let specs_dir = tmp.path().join("SPECS");
    std::fs::create_dir(&specs_dir).unwrap();
    let spec_path = specs_dir.join("test.spec");
    std::fs::write(&spec_path, spec).unwrap();

    // 生产代码里路径硬编码为 /builddir/SPECS；单测用临时目录替换
    let bash = bash.replace("/builddir/SPECS", &specs_dir.to_string_lossy());
    let status = std::process::Command::new("bash")
        .arg("-c")
        .arg(&bash)
        .status()
        .expect("bash should be available");
    assert!(status.success(), "spec patch bash failed: {:?}", status);

    std::fs::read_to_string(&spec_path).unwrap()
}

fn ctx_with_spec_hooks() -> StepContext<'static> {
    let mut hooks = Hooks::default();
    hooks
        .spec_pre
        .insert("prep".to_string(), "echo 'pre-prep-hook'".to_string());
    hooks
        .spec_pre
        .insert("build".to_string(), "echo 'pre-build-hook'".to_string());
    hooks.spec_post.insert(
        "install".to_string(),
        "echo 'post-install-hook'".to_string(),
    );
    hooks
        .spec_post
        .insert("check".to_string(), "echo 'post-check-hook'".to_string());
    // 把 hooks 泄漏成 'static，因为 StepContext 生命周期只要求 Hooks 活得比它久
    let leaked: &'static Hooks = Box::leak(Box::new(hooks));
    StepContext {
        builder_user: "builder",
        build_target: "bb",
        rpm_macros: &[],
        srpm_name: "test-1.0-1.fc42.src.rpm",
        ccache_enabled: false,
        ccache_max_size: "10G",
        dnf_cache_enabled: false,
        has_shared_layer: false,
        hooks: leaked,
        nocheck: false,
        noclean: false,
        nodebuginfo: false,
        target_arch: None,
        local_repo_dir: None,
        follow_logs: false,
        deterministic: false,
        ccache_cold: false,
        builddep_install_weak_deps: true,
        source_date_epoch: None,
        replay_snapshot_domain: false,
    }
}

#[test]
fn patch_spec_injects_profiling_markers() {
    let hooks = Hooks::default();
    let ctx = make_ctx(&hooks);
    let spec =
        "%prep\ndo prep\n%build\ndo build\n%install\ndo install\n%check\ndo check\n%files\n/foo\n";
    let out = run_patch_bash(&ctx, spec);

    assert!(out.contains("echo \"CRBS_RPMBUILD_PHASE prep $(date +%s.%N)\""));
    assert!(out.contains("echo \"CRBS_RPMBUILD_PHASE build $(date +%s.%N)\""));
    assert!(out.contains("echo \"CRBS_RPMBUILD_PHASE install $(date +%s.%N)\""));
    assert!(out.contains("echo \"CRBS_RPMBUILD_PHASE check $(date +%s.%N)\""));
    assert!(out.contains("do prep\n%build"));
}

#[test]
fn patch_spec_injects_spec_hooks() {
    let ctx = ctx_with_spec_hooks();
    let spec =
        "%prep\ndo prep\n%build\ndo build\n%install\ndo install\n%check\ndo check\n%files\n/foo\n";
    let out = run_patch_bash(&ctx, spec);

    // pre hooks 紧跟 profiling echo：hook 文件（0640 builder 属主）经普通 cat 读入后在当前 scriptlet shell 内 eval（保 builder 身份与 sh -e 失败语义）。
    assert!(out.contains("# CRBS_SPEC_HOOK pre prep"));
    assert!(out.contains("eval \"$(cat /crbs-hooks/spec-pre-prep.sh)\""));
    assert!(out.contains("eval \"$(cat /crbs-hooks/spec-pre-build.sh)\""));
    assert!(out.contains("# CRBS_SPEC_HOOK post install"));
    assert!(out.contains("eval \"$(cat /crbs-hooks/spec-post-install.sh)\""));
    assert!(out.contains("eval \"$(cat /crbs-hooks/spec-post-check.sh)\""));
    // post-check 要在 %files 之前
    let idx_post_check = out.find("/crbs-hooks/spec-post-check.sh").unwrap();
    let idx_files = out.find("%files").unwrap();
    assert!(idx_post_check < idx_files);
    // 防泄漏：spec 是 builder 可读文件，hook 体不得被拼进 spec。
    assert!(
        !out.contains("pre-prep-hook")
            && !out.contains("pre-build-hook")
            && !out.contains("post-install-hook")
            && !out.contains("post-check-hook"),
        "hook bodies must not be spliced into the spec: {out}"
    );
}

#[test]
fn patch_spec_does_not_match_pre_as_prep() {
    let hooks = Hooks::default();
    let ctx = make_ctx(&hooks);
    let spec = "%pre\ndo pre\n%prep\ndo prep\n%build\ndo build\n%files\n/foo\n";
    let out = run_patch_bash(&ctx, spec);

    // %pre 前不应有 profiling 标记
    let idx_pre = out.find("%pre\ndo pre").unwrap();
    let idx_prep_marker = out.find("CRBS_RPMBUILD_PHASE prep").unwrap();
    assert!(idx_pre < idx_prep_marker);
    assert!(!out.contains("CRBS_RPMBUILD_PHASE pre "));
}

#[test]
fn patch_spec_is_idempotent() {
    let hooks = Hooks::default();
    let ctx = make_ctx(&hooks);
    let spec = "%prep\ndo prep\n%build\ndo build\n%files\n/foo\n";
    let out1 = run_patch_bash(&ctx, spec);
    let out2 = run_patch_bash(&ctx, &out1);
    let count = out2.matches("CRBS_RPMBUILD_PHASE prep").count();
    assert_eq!(count, 1);
}

/// 敌意字符（引号/换行）hook 体：脚本与 spec 只出现固定路径受控注入行，hook 体不入任何 builder 可读文本（外置后无需 shell_quote 转义，env 只携带静态路径）。
#[test]
fn patch_spec_never_embeds_hook_body_text() {
    let mut hooks = Hooks::default();
    hooks.spec_pre.insert(
        "prep".to_string(),
        "echo 'it'\\''s prep'\nSECRET_TOKEN=abc123\n".to_string(),
    );
    let leaked: &'static Hooks = Box::leak(Box::new(hooks.clone()));
    let ctx = StepContext {
        hooks: leaked,
        ..make_ctx(&hooks)
    };
    let spec = "%prep\ndo prep\n%build\ndo build\n%files\n/foo\n";
    let out = run_patch_bash(&ctx, spec);
    let bash = generate_patch_bash(&ctx);

    assert!(out.contains("eval \"$(cat /crbs-hooks/spec-pre-prep.sh)\""));
    assert!(
        !out.contains("\\''s prep") && !out.contains("SECRET_TOKEN=abc123"),
        "hook body text must not leak into the spec: {out}"
    );
    assert!(
        !bash.contains("\\''s prep") && !bash.contains("SECRET_TOKEN=abc123"),
        "hook body text must not leak into the build script: {bash}"
    );
}

// ===== 确定性模式注入（脚本头 env 基线 / rpmbuild env 前缀 / ccache 守卫）=====

fn make_det_ctx<'a>(hooks: &'a Hooks, deterministic: bool, ccache: bool) -> StepContext<'a> {
    StepContext {
        ccache_enabled: ccache,
        deterministic,
        ..make_ctx(hooks)
    }
}

/// 冷 ccache（reproduce）下各 ccache 站点的 CCACHE_DIR 一律指向容器内临时空目录；普通构建保持 /var/cache/ccache-crbs。
#[test]
fn cold_ccache_swaps_ccache_dir_in_all_ccache_sites() {
    let hooks = Hooks::default();
    let cold = StepContext {
        ccache_enabled: true,
        ccache_cold: true,
        ..make_ctx(&hooks)
    };
    let warm = StepContext {
        ccache_enabled: true,
        ccache_cold: false,
        ..make_ctx(&hooks)
    };
    let pipeline = Pipeline::rpm_build();
    let cold_script = pipeline.compose(&cold);
    let warm_script = pipeline.compose(&warm);

    assert!(cold_script.contains("CCACHE_DIR=/tmp/crbs-ccache-cold"));
    assert!(
        !cold_script.contains("CCACHE_DIR=/var/cache/ccache-crbs"),
        "cold replay must not touch the warm cache dir"
    );
    assert_eq!(
        cold_script
            .matches("CCACHE_DIR=/tmp/crbs-ccache-cold")
            .count(),
        4,
        "ccache-init x2 + rpmbuild x1 + summary x1"
    );
    assert_eq!(
        warm_script
            .matches("CCACHE_DIR=/var/cache/ccache-crbs")
            .count(),
        4,
        "warm build keeps the shared cache dir in all four sites"
    );
}

/// deterministic 脚本头：TZ/哈希种子四件套导出（LC_ALL 已有无条件导出，不重复注入）；非 deterministic 脚本头不含这些导出。
#[test]
fn deterministic_script_header_exports_env_baseline() {
    let hooks = Hooks::default();
    let det = Pipeline::rpm_build().compose(&make_det_ctx(&hooks, true, false));
    assert!(det.contains("export TZ=UTC\n"));
    assert!(det.contains("export PYTHONHASHSEED=0\n"));
    assert!(det.contains("export PERL_HASH_SEED=0\n"));
    assert!(det.contains("export PERL_PERTURB_KEYS=0\n"));
    assert_eq!(det.matches("export LC_ALL=C").count(), 1);

    let plain = Pipeline::rpm_build().compose(&make_det_ctx(&hooks, false, false));
    assert!(!plain.contains("TZ=UTC"));
    assert!(!plain.contains("PYTHONHASHSEED"));
    assert!(!plain.contains("PERL_HASH_SEED"));
}

/// deterministic × rpmbuild：env 前缀补 TZ/哈希种子（sudo env_reset 剥掉脚本头 export，%scriptlet 依赖此处注入）。
#[test]
fn deterministic_rpmbuild_env_prefix_carries_baseline() {
    let hooks = Hooks::default();
    let det = Pipeline::rpm_build().compose(&make_det_ctx(&hooks, true, false));
    assert!(
        det.contains(
            "env LC_ALL=C TZ=UTC PYTHONHASHSEED=0 PERL_HASH_SEED=0 PERL_PERTURB_KEYS=0 rpmbuild"
        ),
        "rpmbuild env prefix must carry the deterministic baseline: {det}"
    );

    let plain = Pipeline::rpm_build().compose(&make_det_ctx(&hooks, false, false));
    assert!(plain.contains("env LC_ALL=C rpmbuild"));
}

/// deterministic × ccache 守卫：CCACHE_COMPILERCHECK=content 注入 +
/// CCACHE_SLOPPY 剔除 time_macros/include_file_ctime 段就位；非 deterministic 无守卫。
#[test]
fn deterministic_ccache_guards_in_rpmbuild_step() {
    let hooks = Hooks::default();
    let det = Pipeline::rpm_build().compose(&make_det_ctx(&hooks, true, true));
    assert!(det.contains("CCACHE_COMPILERCHECK=content"));
    // 剔除脚本段（bash 参数展开 + tr 挤压），scrub 后值经 sudo env 前缀带入 rpmbuild
    assert!(det.contains("_crbs_sloppy=\"${_crbs_sloppy//time_macros/}\""));
    assert!(det.contains("_crbs_sloppy=\"${_crbs_sloppy//include_file_ctime/}\""));
    assert!(det.contains("CCACHE_SLOPPY=\"$_crbs_sloppy\""));
    // 既有注入仍在
    assert!(det.contains("CCACHE_NOHASHDIR=1"));

    // 非 deterministic + ccache：无守卫
    let plain_cc = Pipeline::rpm_build().compose(&make_det_ctx(&hooks, false, true));
    assert!(plain_cc.contains("CCACHE_NOHASHDIR=1"));
    assert!(!plain_cc.contains("CCACHE_COMPILERCHECK"));
    assert!(!plain_cc.contains("_crbs_sloppy"));

    // deterministic 无 ccache：无守卫段
    let det_no_cc = Pipeline::rpm_build().compose(&make_det_ctx(&hooks, true, false));
    assert!(!det_no_cc.contains("CCACHE_COMPILERCHECK"));
    assert!(!det_no_cc.contains("_crbs_sloppy"));
}

/// deterministic 宏组不出现在脚本——注入点在 execution.rs 的 BTreeMap 合并处（StepContext.rpm_macros 是合并后产物），锁定不漂移到 pipeline 层。
#[test]
fn deterministic_macro_group_not_injected_at_pipeline_layer() {
    let hooks = Hooks::default();
    let det = Pipeline::rpm_build().compose(&make_det_ctx(&hooks, true, false));
    assert!(!det.contains("source_date_epoch_from_changelog"));
    assert!(!det.contains("_buildhost"));
}

/// repro-from-srpm：source_date_epoch Some 时 SDE 拼进 rpmbuild 的 sudo env 前缀（env_reset 剥脚本 shell 环境，该前缀是值到达 rpmbuild 的唯一路径）；None 不含 SDE。
#[test]
fn rpmbuild_env_prefix_carries_replay_source_date_epoch() {
    let hooks = Hooks::default();
    let replay = Pipeline::rpm_build().compose(&StepContext {
        source_date_epoch: Some(1_700_000_000),
        ..make_ctx(&hooks)
    });
    assert!(
        replay.contains("env LC_ALL=C SOURCE_DATE_EPOCH='1700000000' rpmbuild"),
        "rpmbuild env prefix must carry the replayed SDE: {replay}"
    );

    let plain = Pipeline::rpm_build().compose(&make_ctx(&hooks));
    assert!(!plain.contains("SOURCE_DATE_EPOCH"));
}
