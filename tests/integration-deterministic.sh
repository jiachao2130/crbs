#!/bin/bash
# CRBS deterministic（确定性构建）集成测试：后端×ccache 四格矩阵全量 + 两负例
#
# 验收矩阵：后端（nspawn/chroot）× ccache（开/关）四格全跑——
# 每格（cell）执行：
#   - 同产品连跑两次 deterministic 构建，逐 RPM sha256 断言相等（同机确定）
#   - build_packages.json 强制落盘（产品 reproduce_enabled=false，模式无视开关）
#     且 sha256/url 100% 非空
#   - builds.deterministic=1 打标（crbs builds show --format json 透出）
#   - -j2 vs -j$(nproc) 双跑断言（并行度无影响的单包实证钉成常驻回归）
# 另含两个与后端/ccache 无关的负例（各跑一次）：
#   - deterministic 产品 --stage ba 提交即拒
#   - deterministic 产品缺 dnf_cache_enabled 配置加载即报错
#
# 注意：本脚本必须在 Linux 构建机上以 root 运行（依赖 rpmbuild / systemd-nspawn /
# dnf 与真实 fedora 镜像源）；本机 macOS 开发环境不跑。
#
# 运行: sudo ./tests/integration-deterministic.sh [test_name_or_prefix ...]
# 单格快速模式（冒烟）：
#   sudo BACKEND=nspawn CCACHE=on  ./tests/integration-deterministic.sh   # 只跑 nspawn+ccache 格
#   sudo BACKEND=chroot CCACHE=off ./tests/integration-deterministic.sh   # 只跑 chroot 无 ccache 格
# （BACKEND / CCACHE 任一未设 = 该维度全跑；两者都未设 = 默认四格全跑。）
# 环境变量：BACKEND=nspawn|chroot、CCACHE=on|off、CRBS（默认 /usr/local/bin/crbs）。

set -euo pipefail

# shellcheck source=lib/integration.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration.sh"

DET_PRODUCT="fedora-det"

# 确定性产品 fixture：reproduce_enabled 故意保持 false（验证模式强制溯源），
# ccache 按格参数化（验收矩阵 ccache 维度），dnf_cache_enabled=true（负例前置）。
# 注意：base_os 首次 init 固定用 ccache=true 的形态（ccache 会进 base_packages），
# 保证 on 格有 ccache 可用；off 格只翻配置开关——构建步骤不加 ccache 前缀，
# base 里装没装 ccache 二进制不影响"本格未启用 ccache"的语义。
write_det_product_config() {
    local ccache_enabled="$1"
    mkdir -p /etc/crbs/products
    cat > "/etc/crbs/products/${DET_PRODUCT}.toml" <<EOF
product = "$DET_PRODUCT"
base_packages = ["rpm-build", "dnf"]

deterministic = true
ccache_enabled = $ccache_enabled
dnf_cache_enabled = true
reproduce_enabled = false

[[repos]]
name = "fedora"
baseurl = "https://mirrors.tuna.tsinghua.edu.cn/fedora/releases/44/Everything/x86_64/os/"
gpgcheck = false
EOF
}

# 本脚本专用定位 helper：共享库的 latest_build_id/latest_result_dir 写死
# `--product fedora`，这里按产品参数化。
# - det_latest_task_id：status 列表（TaskRecord）取首行 id（本地构建任务行）；
# - det_task_build_id：task 详情 JSON 内嵌 builds[0].id（真实 build id，供
#   builds show 用）；
# - det_result_dir：task 详情 JSON 内嵌 builds[0].result_dir 直读（显式回报的
#   确切路径）。不按目录布局猜——引擎实际布局 {result_root}/{product}/{pkg_name}/
#   {ts}-{build_id}，pkg_name 是完整 NEVRA 形态（hello-1.0-1.fc44），第 2 轮验收
#   曾按短名 "hello" 猜目录致 8 例全灭。
det_latest_task_id() {
    $CRBS status --product "$DET_PRODUCT" --format json 2>/dev/null \
        | python3 -c 'import json,sys; data=json.load(sys.stdin); print(data[0]["id"] if data else "")'
}

det_task_build_id() {
    local task_id="$1"
    $CRBS status "$task_id" --format json 2>/dev/null \
        | python3 -c 'import json,sys; d=json.load(sys.stdin); b=d.get("builds") or []; print(b[0]["id"] if b else "")'
}

det_result_dir() {
    local task_id="$1"
    $CRBS status "$task_id" --format json 2>/dev/null \
        | python3 -c 'import json,sys; d=json.load(sys.stdin); b=d.get("builds") or []; print((b[0].get("result_dir") or "") if b else "")'
}

# 摘要文件（进入本测试自己的 result 命名空间，避免同包并发误读兄弟目录）。
rpm_digests() {
    local result_dir="$1"
    (cd "$result_dir/RPMS" && find . -name '*.rpm' | sort | xargs sha256sum) \
        | awk '{print $1, $2}' | sort
}

# ─── 正例（每格执行；当前格由 BACKEND / CCACHE 环境变量决定）───────────

test_deterministic_double_build_byte_identical() {
    local backend="${BACKEND:-chroot}"
    local result_a result_b

    info "Deterministic build #1 (backend=$backend ccache=${CCACHE:-on})..."
    $CRBS build "$SRPM" --product "$DET_PRODUCT" --stage bb --backend "$backend"
    local task_a build_a
    task_a="$(det_latest_task_id)"
    build_a="$(det_task_build_id "$task_a")"
    result_a="$(det_result_dir "$task_a")"
    if [[ -z "$build_a" || -z "$result_a" ]]; then
        error "No build id / result_dir for deterministic build #1 (task=$task_a build=$build_a)"
        return 1
    fi

    info "Deterministic build #2..."
    $CRBS build "$SRPM" --product "$DET_PRODUCT" --stage bb --backend "$backend"
    local task_b build_b
    task_b="$(det_latest_task_id)"
    build_b="$(det_task_build_id "$task_b")"
    result_b="$(det_result_dir "$task_b")"
    if [[ -z "$build_b" || -z "$result_b" ]]; then
        error "No build id / result_dir for deterministic build #2 (task=$task_b build=$build_b)"
        return 1
    fi

    # 逐 RPM sha256 断言相等（文件集合 + 每文件摘要）
    if ! diff <(rpm_digests "$result_a") <(rpm_digests "$result_b"); then
        error "Deterministic double build produced differing RPMs"
        return 1
    fi
    info "RPM byte-identical across two deterministic builds"

    # build_packages.json 强制落盘：产品 reproduce_enabled=false，deterministic
    # 模式必须无视该开关（溯源硬门的输入）。
    local json_a="$result_a/build_packages.json" json_b="$result_b/build_packages.json"
    assert_file_exists "$json_a"
    assert_file_exists "$json_b"
    # sha256/url 100% 非空（溯源硬门的落盘侧体现）
    local bad
    bad="$(python3 -c "
import json
for path in ('${json_a}', '${json_b}'):
    data = json.load(open(path))
    empty = [p['nevra'] for p in data if not p.get('sha256') or not p.get('url')]
    if empty:
        print(path, empty)
        break
" 2>/dev/null || true)"
    if [[ -n "$bad" ]]; then
        error "build_packages.json has empty sha256/url entries: $bad"
        return 1
    fi
    info "build_packages.json present with 100% non-empty sha256/url"

    # builds.deterministic=1（crbs builds show 透出）
    local det_flag
    det_flag="$($CRBS builds show "$build_a" --format json 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin).get("deterministic"))')"
    if [[ "$det_flag" != "True" ]]; then
        error "builds.deterministic not exposed as true (got: $det_flag)"
        return 1
    fi
    info "builds.deterministic=1 visible via builds show"
}

test_deterministic_parallelism_invariance() {
    local backend="${BACKEND:-chroot}"
    local result_a result_b

    info "Deterministic build with _smp_mflags=-j2..."
    $CRBS build "$SRPM" --product "$DET_PRODUCT" --stage bb --backend "$backend" \
        --define "_smp_mflags=-j2"
    local task_a
    task_a="$(det_latest_task_id)"
    result_a="$(det_result_dir "$task_a")"
    if [[ -z "$result_a" ]]; then
        error "No result_dir for -j2 build"
        return 1
    fi

    info "Deterministic build with _smp_mflags=-j$(nproc)..."
    $CRBS build "$SRPM" --product "$DET_PRODUCT" --stage bb --backend "$backend" \
        --define "_smp_mflags=-j$(nproc)"
    local task_b
    task_b="$(det_latest_task_id)"
    result_b="$(det_result_dir "$task_b")"
    if [[ -z "$result_b" ]]; then
        error "No result_dir for -j$(nproc) build"
        return 1
    fi

    if ! diff <(rpm_digests "$result_a") <(rpm_digests "$result_b"); then
        error "Parallelism (-j2 vs -j$(nproc)) changed RPM bytes"
        return 1
    fi
    info "RPM byte-identical across -j2 and -j$(nproc)"
}

# ─── 负例（与后端/ccache 无关，各跑一次）────────────────────────────────

test_deterministic_rejects_stage_ba() {
    if $CRBS build "$SRPM" --product "$DET_PRODUCT" --stage ba \
        --backend "${BACKEND:-chroot}" >/dev/null 2>&1; then
        error "deterministic product must reject --stage ba at submit time"
        return 1
    fi
    info "--stage ba rejected for deterministic product"
}

test_deterministic_requires_dnf_cache() {
    # 独立产品（无 dnf_cache_enabled）：配置加载即报错——不会走到 init/构建，
    # 无需为它准备 base_os。
    local bad_cfg="/etc/crbs/products/fedora-det-nocache.toml"
    cat > "$bad_cfg" <<EOF
product = "fedora-det-nocache"
base_packages = ["rpm-build", "dnf"]
deterministic = true

[[repos]]
name = "fedora"
baseurl = "https://mirrors.tuna.tsinghua.edu.cn/fedora/releases/44/Everything/x86_64/os/"
gpgcheck = false
EOF
    local output
    if output=$($CRBS build "$SRPM" --product fedora-det-nocache --stage bb \
        --backend "${BACKEND:-chroot}" 2>&1); then
        rm -f "$bad_cfg"
        error "deterministic product without dnf_cache_enabled must fail config load"
        return 1
    fi
    rm -f "$bad_cfg"
    if ! echo "$output" | grep -q "dnf_cache_enabled"; then
        error "config error must name dnf_cache_enabled and carry fix guidance: $output"
        return 1
    fi
    info "missing dnf_cache_enabled rejected with fix guidance"
}

list_tests() {
    echo "Available tests in integration-deterministic.sh (per backend×ccache cell):"
    echo "  deterministic_double_build_byte_identical"
    echo "  deterministic_parallelism_invariance"
    echo "Backend-independent (run once):"
    echo "  deterministic_rejects_stage_ba"
    echo "  deterministic_requires_dnf_cache"
    echo ""
    echo "Cells: backend {chroot,nspawn} x ccache {on,off} (restricted via BACKEND= / CCACHE=)"
}

# 解析 ccache 维度环境变量 → "true"/"false"（写进产品 TOML）。
ccache_env_to_bool() {
    case "${1:-}" in
        on | 1 | true) echo "true" ;;
        off | 0 | false) echo "false" ;;
        "") echo "" ;;
        *)
            error "CCACHE must be 'on' or 'off' (got: $1)"
            exit 1
            ;;
    esac
}

main() {
    if [[ "${1:-}" == "--list" || "${1:-}" == "-l" || "${1:-}" == "help" ]]; then
        list_tests
        exit 0
    fi

    if [[ "$EUID" -ne 0 ]]; then
        error "This script must be run as root (Linux build machine only; not run on macOS)"
        exit 1
    fi

    setup

    # fedora-det 首跑需要 base_os：固定用 ccache=true 形态 init 一次（ccache 进
    # base_packages，保证 on 格有 ccache 可用；见 write_det_product_config 注释）。
    # 失败时中止——后续用例全部依赖它。
    write_det_product_config true
    if [[ ! -d "${CRBS_TEST_ROOT}/${DET_PRODUCT}/base" ]]; then
        info "Setup: initializing ${DET_PRODUCT} base_os (with ccache in base)..."
        "$CRBS" init "$DET_PRODUCT" || { error "init $DET_PRODUCT failed"; exit 1; }
    fi

    # 验收矩阵维度：BACKEND / CCACHE 未设 = 该维度全跑（默认四格）；设了 = 单格
    # 快速模式。测试名后缀嵌组合标识（chroot_ccacheon 等），should_run 的前缀
    # 匹配允许按后缀过滤（如传 nspawn 只跑该后端两格）。
    local backends=("${BACKEND:-chroot}" nspawn)
    if [[ -n "${BACKEND:-}" ]]; then
        backends=("$BACKEND")
    fi
    local ccache_vals=("on" "off")
    if [[ -n "${CCACHE:-}" ]]; then
        ccache_vals=("$CCACHE")
    fi
    # 校验 CCACHE 取值合法性（空 = 全跑）
    ccache_env_to_bool "${CCACHE:-}" >/dev/null

    for backend in "${backends[@]}"; do
        if [[ "$backend" != "chroot" && "$backend" != "nspawn" ]]; then
            error "BACKEND must be 'chroot' or 'nspawn' (got: $backend)"
            exit 1
        fi
        for ccache in "${ccache_vals[@]}"; do
            local cell="${backend}_ccache${ccache}"
            export BACKEND="$backend" CCACHE="$ccache"
            # 每格重写产品配置（ccache 维度是配置项）
            write_det_product_config "$(ccache_env_to_bool "$ccache")"

            if should_run "deterministic_double_build_byte_identical_${cell}" "$@"; then
                run_test "deterministic_double_build_byte_identical_${cell}" \
                    test_deterministic_double_build_byte_identical
            fi
            if should_run "deterministic_parallelism_invariance_${cell}" "$@"; then
                run_test "deterministic_parallelism_invariance_${cell}" \
                    test_deterministic_parallelism_invariance
            fi
        done
    done

    # 负例恢复 on 形态配置后跑一次（不依赖 ccache 形态）。backend 固定 chroot：
    # 负例断言的是配置拒绝，须与后端可用性解耦（无 nspawn 的机器上
    # "--backend nspawn" 的失败会伪装成负例通过）。
    export BACKEND=chroot
    write_det_product_config true
    if should_run "deterministic_rejects_stage_ba" "$@"; then
        run_test "deterministic_rejects_stage_ba" test_deterministic_rejects_stage_ba
    fi
    if should_run "deterministic_requires_dnf_cache" "$@"; then
        run_test "deterministic_requires_dnf_cache" test_deterministic_requires_dnf_cache
    fi

    report_results
}

main "$@"
