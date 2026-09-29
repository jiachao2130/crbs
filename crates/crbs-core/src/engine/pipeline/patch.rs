// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! spec 补丁生成：阶段清单与 bash 补丁片段。

use crate::engine::pipeline::hook_file_path;
use crate::engine::pipeline::StepContext;

/// spec 插桩覆盖的 rpmbuild 段名（静态白名单，`hook_files` 同源复用）。
pub(crate) const SPEC_PHASES: &[&str] = &["prep", "build", "install", "check"];

/// 生成 spec patch 的 bash 片段（容器内 awk 执行，host 只生成脚本），每次构建
/// 无条件执行：注入 `CRBS_RPMBUILD_PHASE` 子阶段标记（profiling/失败定位）与
/// 用户 spec hooks；awk 失败清理 `${spec}.crbs-tmp` 残留，调用侧 `|| true` 容错。hook
/// 体不落进 spec（builder 可读）：awk 只拼 `eval "$(cat <hook 文件>)"`，
/// body 在当前 scriptlet shell（builder 身份、原时点、sh -e 失败语义）内执行，
/// hook 变量对同段后续行可见；hook 文件 0640 属主 builder（`write_hook_files`），
/// scriptlet 内普通 `cat` 可读；文件缺失时命令替换为空、eval 无操作（存在才执行）。
pub(crate) fn generate_patch_bash(ctx: &StepContext) -> String {
    let mut env = String::new();
    for phase in SPEC_PHASES {
        let upper = phase.to_uppercase();
        if ctx.hooks.spec_pre.contains_key(*phase) {
            env.push_str(&format!(
                "HOOK_{}={} ",
                upper,
                hook_file_path("spec-pre", phase)
            ));
        }
        if ctx.hooks.spec_post.contains_key(*phase) {
            env.push_str(&format!(
                "HOOK_POST_{}={} ",
                upper,
                hook_file_path("spec-post", phase)
            ));
        }
    }

    format!(
        r##"crbs_patch_spec() {{
    local spec="$1"
    case "$spec" in
        /builddir/SPECS/*.spec) ;;
        *) return 0 ;;
    esac
    local tmp="${{spec}}.crbs-tmp"
    {env}awk '
BEGIN {{
    already = 0
    pending = ""
}}
function flush_post() {{
    if (pending != "" && !already) {{
        print pending
        pending = ""
    }}
}}
# 第一遍扫描：判断是否已经插桩过
FNR == NR {{
    if ($0 ~ /CRBS_RPMBUILD_PHASE|CRBS_SPEC_HOOK/) {{ already = 1 }}
    next
}}
{{
    line = $0
    stripped = line
    sub(/^[ \t]+/, "", stripped)
    if (stripped ~ /^%prep([ \t]|$)/ || stripped ~ /^%build([ \t]|$)/ || stripped ~ /^%install([ \t]|$)/ || stripped ~ /^%check([ \t]|$)/) {{
        flush_post()
        print line
        name = stripped
        sub(/[ \t].*$/, "", name)
        sub(/^%/, "", name)
        if (!already) {{
            print "echo \"CRBS_RPMBUILD_PHASE " name " $(date +%s.%N)\""
            pre = ENVIRON["HOOK_" toupper(name)]
            if (pre != "") {{
                print "# CRBS_SPEC_HOOK pre " name
                print "eval \"$(cat " pre ")\""
            }}
            post = ENVIRON["HOOK_POST_" toupper(name)]
            if (post != "") {{
                pending = "# CRBS_SPEC_HOOK post " name "\neval \"$(cat " post ")\""
            }}
        }}
        next
    }}
    if (stripped ~ /^%files([ \t]|$)/ || stripped ~ /^%changelog([ \t]|$)/) {{
        flush_post()
        print line
        next
    }}
    print line
}}
END {{
    flush_post()
}}
' "$spec" "$spec" > "$tmp" && mv "$tmp" "$spec" || rm -f "$tmp"
}}
for spec in /builddir/SPECS/*.spec; do
    [ -e "$spec" ] || continue
    crbs_patch_spec "$spec" || true
done
"##,
        env = env
    )
}
