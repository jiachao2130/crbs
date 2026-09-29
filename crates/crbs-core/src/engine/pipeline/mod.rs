// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建脚本 Pipeline：每个步骤是纯函数 `fn(&StepContext) -> String`，返回
//! bash 片段；Pipeline 按序拼接并注入 hook 点，生成 `/crbs-build.sh`。
//!
//! hook 体不内联进脚本（0755 对容器内全体可读，管理员 hook 可能含内部
//! URL/凭证）：脚本只引用 `/crbs-hooks/` 固定路径，hook 体由 [`hook_files`]
//! 枚举并落成受限文件（目录 0750/文件 0640、builder 属主，见 `write_hook_files`）。

pub(crate) mod patch;

use crate::config::Hooks;
use crate::engine::pipeline::patch::generate_patch_bash;

/// 容器内 hook 文件固定根路径（overlay 根下的 `/crbs-hooks`）：引擎在脚本
/// 执行前写入，目录 0750、文件 0640、属主 = builder uid:gid（`write_hook_files`）。
/// chroot 无 uid 映射 / nspawn 未开 `--private-users` 时容器内外 uid 一致——
/// builder 与容器 root（DAC_OVERRIDE）可读、其余容器用户不可读；hook 体仍以
/// 原身份执行（步骤 hook = 脚本 shell root、spec hook = scriptlet builder）。
pub(crate) const HOOKS_DIR: &str = "/crbs-hooks";

/// hook 文件的容器内绝对路径（固定命名，脚本字节确定性的来源之一）：
/// `kind`（pre/post/spec-pre/spec-post）与 `target`（pipeline 步骤名或
/// spec 段名）均为代码内静态白名单，不接收用户自由文本，无路径注入面。
pub(crate) fn hook_file_path(kind: &str, target: &str) -> String {
    format!("{HOOKS_DIR}/{kind}-{target}.sh")
}

/// 需要落盘的单个 hook 文件：容器内绝对路径 + 文件内容（hook 体原样，
/// 保证结尾换行）。
pub(crate) struct HookFile {
    pub(crate) container_path: String,
    pub(crate) content: String,
}

/// 枚举本次构建需要落盘的全部 hook 文件：口径与 `compose` /
/// `generate_patch_bash` 的脚本引用一致（步骤名 × pre/post + spec 段名 ×
/// spec-pre/spec-post），指向未知步骤/段名的 hook 被忽略。
pub(crate) fn hook_files(ctx: &StepContext) -> Vec<HookFile> {
    fn push(out: &mut Vec<HookFile>, kind: &str, target: &str, body: &str) {
        let mut content = body.to_string();
        if !content.ends_with('\n') {
            content.push('\n');
        }
        out.push(HookFile {
            container_path: hook_file_path(kind, target),
            content,
        });
    }

    let mut out = Vec::new();
    for step in Pipeline::rpm_build().steps {
        if let Some(body) = ctx.hooks.pre.get(step.name) {
            push(&mut out, "pre", step.name, body);
        }
        if let Some(body) = ctx.hooks.post.get(step.name) {
            push(&mut out, "post", step.name, body);
        }
    }
    for phase in patch::SPEC_PHASES {
        if let Some(body) = ctx.hooks.spec_pre.get(*phase) {
            push(&mut out, "spec-pre", phase, body);
        }
        if let Some(body) = ctx.hooks.spec_post.get(*phase) {
            push(&mut out, "spec-post", phase, body);
        }
    }
    out
}

/// 步骤执行上下文：从 Config + build 参数提取的只读快照，步骤函数经此取数
/// （不依赖 Config 生命周期）。
#[derive(Clone, Copy)]
pub(crate) struct StepContext<'a> {
    pub builder_user: &'a str,
    pub build_target: &'a str,
    pub rpm_macros: &'a [(String, String)],
    pub srpm_name: &'a str,
    pub ccache_enabled: bool,
    pub ccache_max_size: &'a str,
    pub dnf_cache_enabled: bool,
    pub has_shared_layer: bool,
    pub hooks: &'a Hooks,
    pub nocheck: bool,
    pub noclean: bool,
    pub nodebuginfo: bool,
    pub target_arch: Option<&'a str>,
    /// 本地 repo 路径（--reproduce 或 --chain 时传入），容器内挂载点为 /mnt/crbs-repo
    pub local_repo_dir: Option<&'a str>,
    /// 是否将 phase 标记输出到 stdout（--follow-logs）：stdout 由 Rust 侧流式
    /// 持久化进 build.log 并转发终端，脚本内不重定向（避免双写）；关闭时
    /// 标记直接 append 到 build.log。
    pub follow_logs: bool,
    /// 确定性模式：脚本头导出 env 基线、rpmbuild env 前缀带 TZ/哈希种子、
    /// ccache 守卫（CCACHE_COMPILERCHECK=content + CCACHE_SLOPPY 剔除）；宏组
    /// （含 `_buildhost`）在 execution.rs 的 BTreeMap 合并处注入，不经此结构。
    pub deterministic: bool,
    /// 重放走冷 ccache：reproduce 构建的 CCACHE_DIR 指向容器内
    /// 临时空目录（`/tmp/crbs-ccache-cold`），强制真实编译——原（热）vs 重放
    /// （冷）不一致即 verdict=diff。reproduce 一律用 tempfile::TempDir 临时
    /// base_os（两后端同），冷目录落在临时树内随 Drop 移除，无需宿主侧清理。
    pub ccache_cold: bool,
    /// `dnf builddep` weak deps 开关（产品同名配置透传，None 归一 true =
    /// dnf 默认）：false 时 install-deps 追加 `--setopt=install_weak_deps=False`
    /// ——weak deps 非 BR 硬要求，关掉收窄装包集、降低构建环境方差；仅作用
    /// install-deps，base_os init 装包固定同款 setopt 不读此值。
    pub builddep_install_weak_deps: bool,
    /// repro-from-srpm 回放的 `SOURCE_DATE_EPOCH`（SRPM 头 BUILDTIME，epoch 秒）：
    /// `Some` 时拼进 rpmbuild 的 sudo env 前缀——sudo env_reset 剥掉脚本 shell
    /// 环境，时间宏组（use_source_date_epoch_as_buildtime）拿不到值会退回墙钟。
    pub source_date_epoch: Option<i64>,
    /// 复现解析域旗标（replay）：install-deps 的 builddep 追加 `--disablerepo=*`
    /// ——重放密闭 = dnf 侧 repo 唯一源（base 安装走受信 reposdir 同款唯一源），
    /// 非 overlay 源隔离：产品镜像仓仍在 base lower 层 /etc/yum.repos.d，被此
    /// 开关在 dnf 侧禁用不参与解析。dnf5<5.1 无 repo priority，唯一源而非
    /// 优先级压制才与 dnf 版本无关。
    pub replay_snapshot_domain: bool,
}

/// reproduce 模式的冷 ccache 目录（容器内路径，见 `StepContext::ccache_cold`）。
pub(crate) const COLD_CCACHE_DIR: &str = "/tmp/crbs-ccache-cold";

/// 当前构建生效的 CCACHE_DIR 片段（`CCACHE_DIR=<dir> `，带尾随空格）。
fn ccache_dir_env(ctx: &StepContext) -> String {
    format!(
        "CCACHE_DIR={} ",
        if ctx.ccache_cold {
            COLD_CCACHE_DIR
        } else {
            "/var/cache/ccache-crbs"
        }
    )
}

/// 单个构建步骤：名称 + 是否启用 + 生成 bash 片段的函数。
pub(crate) struct Step {
    pub name: &'static str,
    pub enabled: bool,
    pub bash: fn(&StepContext) -> String,
}

/// 构建脚本 Pipeline：持有有序步骤序列，`compose()` 拼接为完整脚本。
pub(crate) struct Pipeline {
    steps: Vec<Step>,
}

fn skip_reason(step_name: &str) -> &'static str {
    match step_name {
        "install-deps" => "shared_layer",
        "ccache-init" | "ccache-summary" => "ccache_disabled",
        _ => "skipped",
    }
}

impl Pipeline {
    /// 创建默认 RPM 构建 Pipeline。
    pub fn rpm_build() -> Self {
        Self {
            steps: vec![
                Step {
                    name: "ccache-init",
                    enabled: true,
                    bash: ccache_init_bash,
                },
                Step {
                    name: "install-srpm",
                    enabled: true,
                    bash: install_srpm_bash,
                },
                Step {
                    name: "install-deps",
                    enabled: true,
                    bash: install_deps_bash,
                },
                Step {
                    name: "build",
                    enabled: true,
                    bash: rpmbuild_bash,
                },
                Step {
                    name: "ccache-summary",
                    enabled: true,
                    bash: ccache_summary_bash,
                },
            ],
        }
    }

    /// 按名称禁用某个步骤（`--reproduce` 两阶段：Phase 1 禁用 build/
    /// ccache-summary 只装依赖，Phase 2 禁用 install-*/ccache-init 只跑构建）。
    pub fn disable(mut self, name: &str) -> Self {
        if let Some(step) = self.steps.iter_mut().find(|s| s.name == name) {
            step.enabled = false;
        }
        self
    }

    /// 将所有步骤拼接为完整 bash 脚本：shebang + `set -e`/pipefail + env 基线，
    /// 每步骤按 `# [hook:pre-…]` → `# [step:…]` → `# [hook:post-…]` 注入，
    /// 前后包 `# CRBS_PHASE_START/END` 时间戳标记。hook 体不进脚本（脚本
    /// 0755 对容器内全体可读，hook 文件仅 builder/root 可读），只引用外置
    /// hook 文件路径。
    pub fn compose(&self, ctx: &StepContext) -> String {
        let mut script = String::with_capacity(2048);
        script.push_str("#!/bin/bash\n");
        script.push_str("set -e\n");
        script.push_str("set -o pipefail\n");
        script.push_str("export LC_ALL=C\n");
        script.push_str(
            "# TERM=dumb: disable dnf/libdnf5 TTY progress bar (no effect on log files, rpmbuild, gcc, make).\n",
        );
        script.push_str("export TERM=dumb\n");

        // 确定性 env 基线：脚本级导出覆盖 root 运行的步骤
        // （dnf builddep 等）与 hook 片段；rpmbuild 自身经 sudo env_reset 不
        // 继承，由 rpmbuild_bash 的 env 前缀同值补齐。LC_ALL=C 上方已导出
        // 不重复；并行度不钉（`_smp_mflags` 保持默认）。单一事实源 =
        // `engine::build::phase::DETERMINISTIC_ENV_BASELINE`。
        if ctx.deterministic {
            script.push_str("# deterministic mode: pin locale/timezone/hash-seed env\n");
            for (k, v) in crate::engine::build::phase::DETERMINISTIC_ENV_BASELINE {
                script.push_str(&format!("export {k}={v}\n"));
            }
        }

        // follow_logs：标记只写 stdout——脚本内再 tee -a 会双写（START/END
        // 解析幂等，SKIP 不幂等，双写会在 profile.json 重复）；非 follow_logs
        // 直接 append 到 build.log。
        let marker_redirect = if ctx.follow_logs {
            ""
        } else {
            " >> /builddir/result/build.log"
        };

        for step in &self.steps {
            if !step.enabled {
                continue;
            }

            // 注入 pre/post hook 调用行（引用外置 hook 文件，hook 体不进
            // 脚本）。`. `（source）语义：同 shell 执行（root）、hook 的
            // export 对后续步骤可见、set -e 下 hook 失败中止脚本。
            let push_hook = |dst: &mut String, pos: &str| {
                dst.push_str(&format!("# [hook:{}-{}]\n", pos, step.name));
                dst.push_str(&format!(". {}\n", hook_file_path(pos, step.name)));
            };

            let body = (step.bash)(ctx);
            if body.trim().is_empty() {
                // 步骤体为空（SharedLayer 命中 / ccache 未启用）：保留 step
                // 注释并注入 skip 标记，hooks 围绕 skip 标记注入——用户显式
                // 配置的 hook 不被静默跳过。
                script.push_str(&format!("# [step:{}]\n", step.name));
                if ctx.hooks.pre.contains_key(step.name) {
                    push_hook(&mut script, "pre");
                }
                script.push_str(&format!(
                    "echo '# CRBS_PHASE_SKIP {} {}'{}\n",
                    step.name,
                    skip_reason(step.name),
                    marker_redirect,
                ));
                if ctx.hooks.post.contains_key(step.name) {
                    push_hook(&mut script, "post");
                }
                continue;
            }

            let mut step_script = String::new();

            if ctx.hooks.pre.contains_key(step.name) {
                push_hook(&mut step_script, "pre");
            }

            step_script.push_str(&format!("# [step:{}]\n", step.name));
            step_script.push_str(&body);
            if !body.ends_with('\n') {
                step_script.push('\n');
            }

            if ctx.hooks.post.contains_key(step.name) {
                push_hook(&mut step_script, "post");
            }

            script.push_str(&format!(
                "echo '# CRBS_PHASE_START {}' \"$(date +%s.%N)\"{}\n",
                step.name, marker_redirect,
            ));
            script.push_str(&step_script);
            script.push_str(&format!(
                "echo '# CRBS_PHASE_END {}' $? \"$(date +%s.%N)\"{}\n",
                step.name, marker_redirect,
            ));
        }

        script
    }
}

// ---- Step 函数：每个返回纯 bash 片段（不含 shebang / set -e）----

/// ccache 初始化：PATH 前缀 + 设置大小限制 + 零化统计。best-effort：base_os
/// 未装 ccache 时 `command -v` 守卫恰好告警一条，ccache 在但命令失败也仅
/// 告警——任何路径都不以 set -e 生效的方式杀死脚本。
fn ccache_init_bash(ctx: &StepContext) -> String {
    if !ctx.ccache_enabled {
        return String::new();
    }
    let warn = "echo \"warning: ccache not active, building without cache\" >&2";
    let dir = ccache_dir_env(ctx);
    format!(
        "export PATH=/usr/lib64/ccache:$PATH\n\
         if command -v ccache >/dev/null 2>&1; then\n  \
         sudo -u {user} env {dir}CCACHE_NOHASHDIR=1 ccache -M {size} || {warn}\n  \
         sudo -u {user} env {dir}CCACHE_NOHASHDIR=1 ccache -z || {warn}\n\
         else\n  {warn}\nfi\n",
        user = crate::util::shell_quote(ctx.builder_user),
        dir = dir,
        size = crate::util::shell_quote(ctx.ccache_max_size),
        warn = warn,
    )
}

/// 安装 SRPM：`rpm -Uvh` 将 spec + sources 释放到 /builddir；`2>&1` 合流
/// stdout+stderr 由 Rust 侧流式写入 build.log（实时可见、失败分类可提取
/// 真实报错）。
fn install_srpm_bash(ctx: &StepContext) -> String {
    let mut script = format!(
        "sudo -u {user} env LC_ALL=C rpm -Uvh --define \"_topdir /builddir\" /builddir/INPUT/{srpm} 2>&1\n",
        user = crate::util::shell_quote(ctx.builder_user),
        srpm = crate::util::shell_quote(ctx.srpm_name),
    );
    // spec 插桩无条件执行：注入 rpmbuild 子阶段标记与用户配置的 spec hooks
    //（幂等、失败兜底 || true，见 patch.rs）。
    script.push_str(&generate_patch_bash(ctx));
    script
}

/// 安装构建依赖：SharedLayer 已提供时跳过。
///
/// `--refresh` 强制回源校验 repo 元数据（比对 repomd.xml）：keepcache 持久化
/// 的 repodata 在 dnf 默认 `metadata_expire`(48h) 窗口内会被判定"新鲜"而不
/// 回源，上游已更新仍用陈旧元数据解析依赖；加 `--refresh` 后元数据未变时
/// 仅极小校验开销，RPM 包体仍由 keepcache 命中。
fn install_deps_bash(ctx: &StepContext) -> String {
    if ctx.has_shared_layer {
        return String::new();
    }
    let dnf_cache_opt = if ctx.dnf_cache_enabled {
        " --setopt=cachedir=/var/cache/dnf"
    } else {
        ""
    };
    let repo_opt = if ctx.local_repo_dir.is_some() {
        if ctx.replay_snapshot_domain {
            // 重放密闭：disablerepo=* 后 crbs-local（记录全集仓）成唯一源——
            // dnf5<5.1 无 repo priority，唯一源与 dnf 版本无关；记录集缺依赖
            // 时 builddep 硬失败，Phase-1 sha 闸门兜底。
            " --disablerepo=* --enablerepo=crbs-local"
        } else {
            // 启用 crbs-local（高优先级）但不禁用其他 repo：cache 完整时 dnf 优先
            // 从 local 取包，不完整时由其他 repo 补充（reproduce 校验会捕获差异）。
            " --enablerepo=crbs-local"
        }
    } else {
        ""
    };
    let weak_deps_opt = if ctx.builddep_install_weak_deps {
        ""
    } else {
        " --setopt=install_weak_deps=False"
    };
    format!(
        "dnf builddep -y --refresh{}{} --setopt=keepcache=True{} /builddir/SPECS/*.spec 2>&1\n",
        dnf_cache_opt, repo_opt, weak_deps_opt,
    )
}

/// rpmbuild 子阶段插桩过滤器：在每条 `Executing(%xxx)` 边界行前回写一条
/// `# CRBS_SUBPHASE %xxx <epoch-ts>` 标记（解析器 → 时间线分段条），原行
/// 照常输出；fflush 逐行冲刷保证 live 流序，gawk 在 REQUIRED_BASE_PACKAGES。
const RPMBUILD_SUBPHASE_FILTER: &str = r##"awk '
/^Executing\(%/ {
    name = $0
    sub(/^Executing\(/, "", name)
    sub(/\).*/, "", name)
    ("date +%s.%N" | getline ts)
    close("date +%s.%N")
    printf "# CRBS_SUBPHASE %s %s\n", name, ts
}
{ print; fflush() }
'"##;

/// install-post 链挂载点：把归一化追加到 `%__brp_strip_static_archive`，使其
/// 成为"原 brp 命令 + 归一化"；`crbs_normalize_payload` 未定义时展开为发行版
/// 原定义，对既有构建零行为变更。
///
/// 挂载点不可换到 canonical arch 槽（os 之前）：该槽在
/// `brp-strip-static-archive` 之前执行，后者会重新 strip .a 并重打成员
/// mtime/uid/gid（实测 pcre2-devel 四架构漂移）；本位置是链内最后一个 .a/zip
/// 触碰点之后的槽位，归一化内容碰脏的外层 mtime 仍由 payload 生成期的
/// clamp_mtime 收口。
///
/// 副作用：不定义 `__arch_install_post`，cuos arch 槽默认的 check-buildroot
/// 恢复执行（多一道 buildroot 健全性检查）。
///
/// ponytail: 机制要求 base 的 brp 链以 `__brp_strip_static_archive` 路径宏引用
/// 该步骤（cuos vendor 宏满足）；无此引用的 base 会静默跳过。改挂
/// `%__spec_install_post` 尾需重嵌 debug → arch → os（含 cuos 私有
/// cuos_delete_rpath 位），跨 base 脆弱，故不采。
const INSTALL_POST_HOOK_DEFINE: &str = "__brp_strip_static_archive \
    %{_rpmconfigdir}/brp-strip-static-archive %{__strip}%{?crbs_normalize_payload:\n    %{crbs_normalize_payload}}";

fn rpmbuild_bash(ctx: &StepContext) -> String {
    // ccache env 前缀 + 守卫（deterministic × ccache 共存前提 = 缓存键 ⊇
    // 所有影响输出的输入）：追加 CCACHE_COMPILERCHECK=content（内容哈希取代
    // mtime/size），并从 CCACHE_SLOPPY 剔除 time_macros / include_file_ctime
    //（时间类 sloppiness 会让缓存键漏掉时间输入）。SLOPPY 的可能来源是
    // pre-build hook 的 export，spec 内自行 export 是残余风险、由冷
    // ccache 重放检测。剔除在 sudo 之前做、经 env 前缀带入 rpmbuild
    //（sudo env_reset 不继承脚本 shell 的 export）。
    let mut prelude = String::new();
    let mut ccache_sudo_env = String::new();
    if ctx.ccache_enabled {
        ccache_sudo_env.push_str(&ccache_dir_env(ctx));
        ccache_sudo_env.push_str("CCACHE_NOHASHDIR=1 ");
        if ctx.deterministic {
            ccache_sudo_env.push_str("CCACHE_COMPILERCHECK=content ");
            prelude.push_str(
                "# deterministic x ccache guard: strip time-based sloppiness\n\
                 _crbs_sloppy=\"${CCACHE_SLOPPY:-}\"\n\
                 _crbs_sloppy=\"${_crbs_sloppy//time_macros/}\"\n\
                 _crbs_sloppy=\"${_crbs_sloppy//include_file_ctime/}\"\n\
                 _crbs_sloppy=\"$(printf '%s' \"$_crbs_sloppy\" | tr -s ':,')\"\n",
            );
            ccache_sudo_env.push_str("CCACHE_SLOPPY=\"$_crbs_sloppy\" ");
        }
        ccache_sudo_env.push_str("PATH=/usr/lib64/ccache:$PATH ");
    }

    // deterministic env 前缀：sudo env_reset 剥掉脚本头 export 的 TZ/哈希种子，
    // 这里对 rpmbuild 及其 %scriptlet 子进程同值补齐（单一事实源 =
    // DETERMINISTIC_ENV_BASELINE）。
    let mut det_env = if ctx.deterministic {
        let mut s = crate::engine::build::phase::DETERMINISTIC_ENV_BASELINE
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");
        s.push(' ');
        s
    } else {
        String::new()
    };
    // repro-from-srpm：SDE 同受 env_reset 影响，须与 deterministic 前缀同位
    // 拼接才能到达 rpmbuild；值经 shell_quote 防御（来源是 rpm 头整数）。
    if let Some(epoch) = ctx.source_date_epoch {
        det_env.push_str(&format!(
            "SOURCE_DATE_EPOCH={} ",
            crate::util::shell_quote(&epoch.to_string())
        ));
    }

    // 宏 --define 整体作为一个单引号参数传给 rpmbuild（避免空格拆 argv）；
    // rpm_macros 由调用方按 key 排序传入（execution.rs 的 BTreeMap），
    // 拼接出的脚本逐字节确定——reproduce/provenance 依赖。
    // install-post 挂载点最先注入：用户/CLI --define 的 __brp_strip_static_archive
    // 排在其后仍可覆盖（覆盖口子与核心宏同口径保留）。
    let mut macros = String::new();
    macros.push_str(&format!(
        "    --define {} \\\n",
        crate::util::shell_quote(INSTALL_POST_HOOK_DEFINE)
    ));
    for (key, value) in ctx.rpm_macros {
        let def = format!("{} {}", key, value);
        macros.push_str(&format!(
            "    --define {} \\\n",
            crate::util::shell_quote(&def)
        ));
    }

    let target_arg = ctx
        .target_arch
        .map(|a| format!("    --target {} \\\n", crate::util::shell_quote(a)))
        .unwrap_or_default();

    let mut opts = String::new();
    if ctx.nocheck {
        opts.push_str("    --nocheck \\\n");
    }
    if ctx.nodebuginfo {
        opts.push_str("    --nodebuginfo \\\n");
    }
    // --noclean：跳过 distro 收尾清理段（spec %clean 与 rpm 4.18 内建
    // rmbuild）。一次性 overlay 环境里 BUILD 树回收由引擎 teardown 统一负责
    // （umount/rm 整实例），清理段没有存在意义；rmbuild 对非 root builder 是
    // 已知失败源——spec 把目录 chmod 成 644 时 rm 无法穿越，产物完好却被判
    // 失败（oe2403sp1 protobuf 四架构实测）。两段都在全部 "Wrote:" 之后运行、
    // 与产物零关系。默认关，与 nocheck 同链路（CLI/product 配置）。
    if ctx.noclean {
        opts.push_str("    --noclean \\\n");
    }

    // stage 的 `-` 与目标阶段（bb/bs/ba）同引号，确保同一 shell word。
    let stage = format!("-{}", crate::util::shell_quote(ctx.build_target));
    // 子阶段插桩：Executing(%xxx) 行无时间戳，管道上加静态 awk 过滤器回写
    // 带时间戳的 CRBS_SUBPHASE 标记（见常量注释）；pipefail 全局开启，
    // rpmbuild 退出码经管道传播。
    format!(
        "{prelude}sudo -u {user} env LC_ALL=C {det_env}{ccache_env}rpmbuild {stage} \\\n{macros}{target}{opts}    /builddir/SPECS/*.spec | {subphase_filter}\n",
        prelude = prelude,
        user = crate::util::shell_quote(ctx.builder_user),
        det_env = det_env,
        ccache_env = ccache_sudo_env,
        stage = stage,
        macros = macros,
        target = target_arg,
        opts = opts,
        subphase_filter = RPMBUILD_SUBPHASE_FILTER,
    )
}

/// ccache 统计摘要。纯遥测、best-effort：`command -v` 守卫避免 ccache 缺失
/// 产生 exit 127 杀死脚本，统计失败也 `|| true` 静默兜底；守卫的 `PATH=`
/// 前缀与下方 sudo env 调用环境对齐（本步骤不 export）。
fn ccache_summary_bash(ctx: &StepContext) -> String {
    if !ctx.ccache_enabled {
        return String::new();
    }
    let dir = ccache_dir_env(ctx);
    format!(
        "if PATH=/usr/lib64/ccache:$PATH command -v ccache >/dev/null 2>&1; then\n  \
         sudo -u {user} env LC_ALL=C {dir}CCACHE_NOHASHDIR=1 \
         PATH=/usr/lib64/ccache:$PATH ccache -s || true\nfi\n",
        user = crate::util::shell_quote(ctx.builder_user),
        dir = dir,
    )
}

#[cfg(test)]
mod tests;
