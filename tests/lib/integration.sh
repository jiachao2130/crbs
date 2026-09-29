#!/bin/bash
# CRBS 集成测试共享库
# 被 tests/integration-*.sh 脚本 source 使用。
# 约定：clean 在非 TTY 必须带 --yes，且不吞失败（force-clean 要真正生效、
# 失败要可见）；clean 容忍首跑 not-found（产品未 init 是合法路径）。
# fixture 统一 pin crbs_root：引擎与 server root 分离后引擎默认根是
# /var/lib/crbs-engine，不 pin 则本库与各脚本的 /var/lib/crbs 路径全部落空。

set -euo pipefail

CRBS=${CRBS:-/usr/local/bin/crbs}
# 测试统一 pin 的 crbs_root（setup() 写入 /etc/crbs/crbs.toml；与
# gc_policy.sh / integration-local-daemon.sh 的 fixture 同值）。测试内的
# 确定性路径（base_os 检测、fedora-clean 产品根、reproduce cache 清理）
# 一律从本变量派生。
CRBS_TEST_ROOT=${CRBS_TEST_ROOT:-/var/lib/crbs}
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES="$(cd "$LIB_DIR/.." && pwd)/fixtures"
SRPM="$FIXTURES/hello/hello-1.0-1.fc44.src.rpm"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

PASS=0
FAIL=0

info() { echo -e "${GREEN}[INFO]${NC} $*"; }
error() { echo -e "${RED}[FAIL]${NC} $*"; }

assert_eq() {
    local expected="$1"
    local actual="$2"
    local msg="${3:-}"
    if [[ "$expected" == "$actual" ]]; then
        return 0
    else
        error "assert_eq failed: expected='$expected' actual='$actual' ${msg}"
        return 1
    fi
}

assert_file_exists() {
    if [[ -f "$1" ]]; then
        return 0
    else
        error "File not found: $1"
        return 1
    fi
}

run_test() {
    local name="$1"
    shift
    echo ""
    info "Running: $name"
    if "$@"; then
        echo -e "${GREEN}[PASS]${NC} $name"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}[FAIL]${NC} $name"
        FAIL=$((FAIL + 1))
    fi
}

# ─── setup / teardown ──────────────────────────────────────────

# clean 首跑容忍 not-found：产品尚未 init 时 clean 报 ValidationFailed
# "product not found: ..."（clean.rs：product_root 不存在），这是首跑的
# 合法路径——若不容忍，setup 会在 init 前中止。除该
# 文案外的失败（active build 守卫等）照常暴露并中止 setup。
clean_product_or_first_run() {
    local product="$1" output
    if output=$($CRBS clean "$product" --yes 2>&1); then
        return 0
    fi
    if echo "$output" | grep -q "product not found"; then
        info "Setup: clean $product skipped (product not initialized; first run)"
        return 0
    fi
    error "Setup: clean $product failed: $output"
    return 1
}

setup() {
    info "Setup: generating SRPM if needed..."
    if [[ ! -f "$SRPM" ]]; then
        (cd "$FIXTURES/hello" && rpmbuild -bs --define "_srcrpmdir ." --define "_sourcedir ." --define "dist .fc44" hello.spec)
    fi
    assert_file_exists "$SRPM"

    info "Setup: pinning crbs_root to ${CRBS_TEST_ROOT}..."
    mkdir -p /etc/crbs
    # 引擎默认 root 是 /var/lib/crbs-engine；不 pin 会让本库与各
    # 测试脚本的 /var/lib/crbs 确定性路径（base_os 检测、cache 清理）落在
    # 不存在的位置上静默空转。
    cat > /etc/crbs/crbs.toml <<EOF
crbs_root = "$CRBS_TEST_ROOT"
EOF

    info "Setup: ensuring product config exists..."
    mkdir -p /etc/crbs/products
    # 使用 fedora 产品配置（已验证可用），但独立测试结果目录
    cat > "/etc/crbs/products/fedora.toml" <<EOF
product = "fedora"
base_packages = ["rpm-build", "dnf"]

ccache_enabled = true
dnf_cache_enabled = true
reproduce_enabled = true

[rpm_macros]
distcore = ".crbs"

[[repos]]
name = "fedora"
baseurl = "https://mirrors.tuna.tsinghua.edu.cn/fedora/releases/44/Everything/x86_64/os/"
gpgcheck = false
EOF

    # 为 clean 测试准备一个独立产品，避免把 fedora 的 base_os 清掉。
    # 这样常规测试可以复用 fedora 的 base_os，显著减少重复跑测试的时间。
    if [[ ! -f "/etc/crbs/products/fedora-clean.toml" ]]; then
        cat > "/etc/crbs/products/fedora-clean.toml" <<EOF
product = "fedora-clean"
base_packages = []

[[repos]]
name = "fedora"
baseurl = "https://mirrors.tuna.tsinghua.edu.cn/fedora/releases/44/Everything/x86_64/os/"
gpgcheck = false
EOF
    fi
    # 产品根目录在 {crbs_root}/{product}（crbs_root 已 pin 为 CRBS_TEST_ROOT，
    # 见上方 crbs.toml）。
    mkdir -p "$CRBS_TEST_ROOT/fedora-clean"

    # 默认复用已有的 fedora base_os；显式设置 CRBS_TEST_FORCE_CLEAN=1 可强制重置。
    # 若产品配置发生变更（repos / base_packages 等），也强制重建，避免 repo_id 与
    # 当前配置不匹配导致 package URL 解析失败。
    local fedora_base_os="$CRBS_TEST_ROOT/fedora/base"
    local config_fingerprint
    config_fingerprint="$(sha256sum /etc/crbs/products/fedora.toml | awk '{print $1}')"
    local saved_fingerprint=""
    if [[ -f "$fedora_base_os/.config-fingerprint" ]]; then
        saved_fingerprint="$(cat "$fedora_base_os/.config-fingerprint")"
    fi

    if [[ -n "${CRBS_TEST_FORCE_CLEAN:-}" ]]; then
        info "Setup: CRBS_TEST_FORCE_CLEAN set, cleaning fedora..."
        # --yes：非 TTY 下 clean 的硬性要求；clean 失败除首跑 not-found 外
        # 一律当场暴露——active build 守卫触发意味着环境有并发冲突。
        clean_product_or_first_run fedora
    elif [[ -d "$fedora_base_os" && -f "$fedora_base_os/.packages.json" && "$config_fingerprint" == "$saved_fingerprint" ]]; then
        info "Setup: reusing existing fedora base_os"
    else
        if [[ "$config_fingerprint" != "$saved_fingerprint" && -d "$fedora_base_os" ]]; then
            info "Setup: fedora product config changed, cleaning base_os to rebuild..."
        else
            info "Setup: fedora base_os missing or unhealthy, cleaning to force rebuild..."
        fi
        clean_product_or_first_run fedora
    fi

    # 若 base_os 不存在（被清理或首次运行），先 eager init 以建立 base_os 并保存指纹，
    # 使后续测试运行可以复用。
    if [[ ! -d "$fedora_base_os" ]]; then
        info "Setup: initializing fedora base_os..."
        $CRBS init fedora >/dev/null 2>&1 || true
    fi

    # 在 base_os 重建后保存配置指纹，使后续测试运行可以复用。
    if [[ -d "$fedora_base_os" ]]; then
        echo "$config_fingerprint" > "$fedora_base_os/.config-fingerprint"
    fi
}

# 获取最近一次成功构建的 build_id
latest_build_id() {
    $CRBS status --product fedora --format json 2>/dev/null \
        | python3 -c 'import json,sys; data=json.load(sys.stdin); print(data[0]["id"])' 2>/dev/null
}

# 获取最近一次成功构建的 result_dir
latest_result_dir() {
    $CRBS status --product fedora --format json 2>/dev/null \
        | python3 -c 'import json,sys; data=json.load(sys.stdin); print(data[0]["result_dir"])' 2>/dev/null
}

# 判断当前测试是否应该执行：无参数时全量；有参数时名称匹配任一参数前缀即可。
should_run() {
    local name="$1"
    shift
    if [[ $# -eq 0 ]]; then
        return 0
    fi
    for pattern in "$@"; do
        if [[ "$name" == "$pattern"* ]]; then
            return 0
        fi
    done
    return 1
}

# 打印最终汇总并退出。
report_results() {
    echo ""
    info "Results: PASS=$PASS FAIL=$FAIL"
    if [[ $FAIL -gt 0 ]]; then
        exit 1
    fi
}
