#!/bin/bash
# --format json 与退出码语义的集成测试
#
# 验证：
#   1. crbs build --format json 输出合法 JSON 且结构正确
#   2. 成功构建退出码为 0
#   3. 构建失败退出码为语义码（非 1）
#   4. crbs build --reproduce --format json 输出 verification 结构
#     （字段：environment_packages / restored_packages / produced_rpms）
#   5. text 模式与 json 模式退出码一致
#
# reproduce verification 字段为 environment_packages/restored_packages/
# produced_rpms（不做 sha256 相等断言）。
#
# 运行: sudo ./tests/output_format.sh
# 也可指定 backend: sudo BACKEND=nspawn ./tests/output_format.sh

set -euo pipefail

CRBS=${CRBS:-/usr/local/bin/crbs}
FIXTURES="$(cd "$(dirname "$0")" && pwd)/fixtures"
SRPM="$FIXTURES/hello/hello-1.0-1.fc44.src.rpm"
PRODUCT="fedora"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[FAIL]${NC} $*"; }

run_test() {
    local name="$1"; shift
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

# ─── 前置检查 ──────────────────────────────────────────────────

if [[ "$EUID" -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

for tool in jq crbs rpmbuild; do
    command -v "$tool" >/dev/null || { error "missing tool: $tool"; exit 1; }
done

# ─── setup ─────────────────────────────────────────────────────

setup() {
    info "Setup: generating SRPM if needed..."
    if [[ ! -f "$SRPM" ]]; then
        (cd "$FIXTURES/hello" && rpmbuild -bs --define "_srcrpmdir ." --define "_sourcedir ." --define "dist .fc44" hello.spec)
    fi

    info "Setup: ensuring product config exists..."
    mkdir -p /etc/crbs/products
    if [[ ! -f "/etc/crbs/products/$PRODUCT.toml" ]]; then
        cat > "/etc/crbs/products/$PRODUCT.toml" <<EOF
product = "$PRODUCT"
base_packages = ["rpm-build", "dnf"]

# reproduce 的 provenance（URL/SHA256/build_packages.json）写入受此门控，
# 默认 false——不开启则 build 无 provenance 可复现，test 4 的 verification
# 断言在干净机器上必失败。
reproduce_enabled = true

[[repos]]
name = "fedora"
baseurl = "https://mirrors.tuna.tsinghua.edu.cn/fedora/releases/44/Everything/x86_64/os/"
gpgcheck = false
EOF
    fi

    $CRBS init "$PRODUCT" 2>/dev/null || true
}

setup

# ─── 测试 1：build --format json 输出合法 JSON + 退出码 0 ────────

test_build_json_success() {
    info "Building with --format json..."
    local output exit_code
    set +e
    output=$($CRBS build "$SRPM" --product "$PRODUCT" --format json 2>/dev/null)
    exit_code=$?
    set -e

    # 从输出中提取 JSON 部分（跳过可能混入的 tracing 日志行）
    local json
    json=$(echo "$output" | sed -n '/^{/,$ p' | sed '/^$/d')

    if [[ -z "$json" ]]; then
        error "No JSON output found"
        return 1
    fi

    # 验证 JSON 合法性
    if ! echo "$json" | jq . >/dev/null 2>&1; then
        error "Invalid JSON output"
        echo "$json" | head -5
        return 1
    fi

    # 验证关键字段
    local cmd outcome
    cmd=$(echo "$json" | jq -r '.command')
    outcome=$(echo "$json" | jq -r '.outcome')

    if [[ "$cmd" != "build" ]]; then
        error "command field is '$cmd', expected 'build'"
        return 1
    fi
    if [[ "$outcome" != "succeeded" ]]; then
        error "outcome is '$outcome', expected 'succeeded'"
        return 1
    fi

    # 验证 packages 数组有 build_id
    local pkg_count build_id
    pkg_count=$(echo "$json" | jq '.packages | length')
    build_id=$(echo "$json" | jq -r '.packages[0].build_id // empty')
    if [[ "$pkg_count" -lt 1 ]]; then
        error "packages array is empty"
        return 1
    fi
    if [[ -z "$build_id" ]]; then
        error "packages[0].build_id is missing"
        return 1
    fi

    # 验证退出码
    if [[ "$exit_code" -ne 0 ]]; then
        error "exit code is $exit_code, expected 0"
        return 1
    fi

    info "JSON valid, outcome=$outcome, build_id=$build_id, exit=$exit_code"
    return 0
}

run_test "build --format json (success)" test_build_json_success

# ─── 测试 2：text 与 json 模式退出码一致 ───────────────────────

test_exit_code_consistency() {
    info "Building with text mode..."
    set +e
    $CRBS build "$SRPM" --product "$PRODUCT" >/dev/null 2>&1
    local text_exit=$?

    info "Building with json mode..."
    $CRBS build "$SRPM" --product "$PRODUCT" --format json >/dev/null 2>&1
    local json_exit=$?
    set -e

    if [[ "$text_exit" -ne "$json_exit" ]]; then
        error "exit codes differ: text=$text_exit json=$json_exit"
        return 1
    fi

    info "Both modes exit with code $text_exit"
    return 0
}

run_test "exit code consistency (text vs json)" test_exit_code_consistency

# ─── 测试 3：build 失败时退出码为语义码（非 1） ─────────────────

test_build_failure_exit_code() {
    # 用不存在的 SRPM 触发失败
    info "Building nonexistent SRPM..."
    set +e
    $CRBS build /nonexistent.src.rpm --product "$PRODUCT" >/dev/null 2>&1
    local exit_code=$?
    set -e

    # 期望语义化退出码：前置校验 / 输入类错误应映射到 4（USAGE），
    # 总之不能是未分类的 1。
    if [[ "$exit_code" -eq 0 ]]; then
        error "exit code is 0, expected non-zero for failed build"
        return 1
    fi
    if [[ "$exit_code" -eq 1 ]]; then
        error "exit code is 1, expected a semantic exit code"
        return 1
    fi

    info "Failed build exits with code $exit_code (semantic code as expected)"
    return 0
}

run_test "build failure exit code (non-zero)" test_build_failure_exit_code

# ─── 测试 4：reproduce --format json 输出 verification 结构 ──────

test_reproduce_json() {
    # 先确保有一个成功的 build
    local build_output build_id
    set +e
    build_output=$($CRBS build "$SRPM" --product "$PRODUCT" --format json 2>/dev/null)
    local build_exit=$?
    set -e
    build_id=$(echo "$build_output" | sed -n '/^{/,$ p' | jq -r '.packages[0].build_id // empty')

    if [[ -z "$build_id" || "$build_exit" -ne 0 ]]; then
        warn "Could not get build_id for reproduce test, skipping"
        return 0
    fi

    info "Reproducing build $build_id with --format json..."
    local output exit_code
    set +e
    output=$($CRBS build --reproduce "$build_id" --product "$PRODUCT" --format json 2>/dev/null)
    exit_code=$?
    set -e

    local json
    json=$(echo "$output" | sed -n '/^{/,$ p' | sed '/^$/d')

    if [[ -z "$json" ]]; then
        error "No JSON output from reproduce"
        return 1
    fi

    if ! echo "$json" | jq . >/dev/null 2>&1; then
        error "Invalid JSON from reproduce"
        return 1
    fi

    local mode outcome
    mode=$(echo "$json" | jq -r '.mode')
    outcome=$(echo "$json" | jq -r '.outcome')

    if [[ "$mode" != "reproduce" ]]; then
        error "mode is '$mode', expected 'reproduce'"
        return 1
    fi
    if [[ "$outcome" != "succeeded" ]]; then
        error "outcome is '$outcome', expected 'succeeded'"
        return 1
    fi

    # 验证 verification 结构（新语义：环境包 / 缓存恢复 / 产出 RPM 计数）。
    # environment_packages = 原始构建 build_packages.json 的条目数（锁定
    # 的环境快照清单，reproduce.rs build_verification 口径），与"URL 回退
    # 计入"无关；restored_packages 允许为 0：reproduce cache 未启用或
    # miss 时按 URL 回退下载，不计入 cache 恢复数。
    local env_pkgs restored produced
    env_pkgs=$(echo "$json" | jq -r '.verification.environment_packages')
    restored=$(echo "$json" | jq -r '.verification.restored_packages')
    produced=$(echo "$json" | jq -r '.verification.produced_rpms')
    if ! [[ "$env_pkgs" =~ ^[0-9]+$ && "$restored" =~ ^[0-9]+$ && "$produced" =~ ^[0-9]+$ ]]; then
        error "verification fields missing or non-numeric: env=$env_pkgs restored=$restored produced=$produced"
        return 1
    fi
    if [[ "$env_pkgs" -lt 1 ]]; then
        error "verification.environment_packages is $env_pkgs, expected >= 1"
        return 1
    fi
    if [[ "$produced" -lt 1 ]]; then
        error "verification.produced_rpms is $produced, expected >= 1"
        return 1
    fi

    if [[ "$exit_code" -ne 0 ]]; then
        error "reproduce exit code is $exit_code, expected 0"
        return 1
    fi

    info "Reproduce JSON valid: mode=$mode outcome=$outcome env_pkgs=$env_pkgs restored=$restored produced=$produced"
    return 0
}

run_test "reproduce --format json (verification)" test_reproduce_json

# ─── 总结 ──────────────────────────────────────────────────────

echo ""
if [[ $FAIL -eq 0 ]]; then
    info "All $PASS test(s) PASSED"
    exit 0
else
    error "$FAIL test(s) FAILED, $PASS passed"
    exit 1
fi
