#!/bin/bash
# spec 插桩（rpmbuild 子阶段 profiling + hooks.spec）集成测试
#
# 验证（插桩无条件执行，无 profile 旗标）：
#   1. 普通构建即生成 profile.json，包含 build-prep/build-build/build-install
#   2. [hooks.spec.pre/post] 配置的 bash 会出现在 build.log 中
#   3. 未配 [hooks.spec] 时 build.log 无 CRBS_SPEC_HOOK 注入
#     （CRBS_RPMBUILD_PHASE 标记则恒存在）
#
# 运行: sudo ./tests/spec_patch.sh
# 也可指定 backend: sudo BACKEND=nspawn ./tests/spec_patch.sh

set -euo pipefail

CRBS=${CRBS:-/usr/local/bin/crbs}
FIXTURES="$(cd "$(dirname "$0")" && pwd)/fixtures"
SRPM="$FIXTURES/hello/hello-1.0-1.fc44.src.rpm"
PRODUCT="fedora"
REPO_URL="${CRBS_TEST_REPO:-https://mirrors.tuna.tsinghua.edu.cn/fedora/releases/44/Everything/x86_64/os/}"

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

for tool in jq rpmbuild "$CRBS"; do
    if [[ "$tool" == /* || "$tool" == ./* ]]; then
        [[ -x "$tool" ]] || { error "missing tool: $tool"; exit 1; }
    else
        command -v "$tool" >/dev/null || { error "missing tool: $tool"; exit 1; }
    fi
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

[[repos]]
name = "fedora"
baseurl = "$REPO_URL"
gpgcheck = false
EOF
    fi

    local base_os="/var/lib/crbs/$PRODUCT/base"
    if [[ ! -d "$base_os" && -n "${SKIP_IF_NO_NETWORK:-}" ]]; then
        warn "base_os missing and SKIP_IF_NO_NETWORK is set; skipping integration tests"
        exit 0
    fi

    $CRBS init "$PRODUCT" 2>/dev/null || true
}

# ─── helpers ───────────────────────────────────────────────────

last_task_id() {
    # 取当前用户最近一条构建记录 id（JSON 中第一行的 id 字段）
    $CRBS status --all --format json 2>/dev/null | jq -r '.records[0].id'
}

# ─── tests ─────────────────────────────────────────────────────

test_profile_subphases() {
    # 插桩无条件执行：普通构建即写 profile.json（无需任何旗标）。
    info "Building hello (instrumentation is unconditional)..."
    local out
    out=$(mktemp)
    $CRBS build "$SRPM" --product "$PRODUCT" --format json --backend "${BACKEND:-chroot}" > "$out"
    local task_id result_dir
    task_id=$(jq -r '.packages[0].build_id' "$out")
    result_dir=$(jq -r '.packages[0].result_dir' "$out")
    rm -f "$out"

    if [[ -z "$task_id" || "$task_id" == "null" ]]; then
        error "build did not produce build_id"
        return 1
    fi

    local profile
    profile="$result_dir/profile.json"
    if [[ ! -f "$profile" ]]; then
        error "profile.json missing: $profile"
        return 1
    fi

    for phase in build-prep build-build build-install; do
        if ! jq -e --arg phase "$phase" '.phases[] | select(.name == $phase)' "$profile" >/dev/null; then
            error "missing subphase $phase in profile.json"
            return 1
        fi
    done

    info "profile.json contains expected subphases"
}

test_spec_hooks() {
    # 临时产品配置，只加 spec hooks
    local hook_product="${PRODUCT}-spec-hooks"
    cat > "/etc/crbs/products/$hook_product.toml" <<EOF
product = "$PRODUCT"
base_packages = ["rpm-build", "dnf"]

[[repos]]
name = "fedora"
baseurl = "$REPO_URL"
gpgcheck = false

[hooks.spec.pre]
prep = "echo 'CRBS_TEST_PRE_PREP'"
build = "echo 'CRBS_TEST_PRE_BUILD'"

[hooks.spec.post]
install = "echo 'CRBS_TEST_POST_INSTALL'"
EOF

    info "Building hello with [hooks.spec]..."
    local out
    out=$(mktemp)
    $CRBS build "$SRPM" --product "$hook_product" --format json --backend "${BACKEND:-chroot}" > "$out"
    local result_dir
    result_dir=$(jq -r '.packages[0].result_dir' "$out")
    rm -f "$out"

    local log
    log="$result_dir/build.log"
    for marker in CRBS_TEST_PRE_PREP CRBS_TEST_PRE_BUILD CRBS_TEST_POST_INSTALL; do
        if ! grep -q "$marker" "$log"; then
            error "missing spec hook marker $marker in build.log"
            return 1
        fi
    done

    info "build.log contains all spec hook markers"
}

test_no_hook_injection_without_hooks_config() {
    # 未配 [hooks.spec] 时：插桩标记恒在（无条件插桩），但不得出现
    # CRBS_SPEC_HOOK 注入（patch.rs 仅在 hooks 配置存在时生成）。
    info "Building hello without [hooks.spec]..."
    local out
    out=$(mktemp)
    $CRBS build "$SRPM" --product "$PRODUCT" --format json --backend "${BACKEND:-chroot}" > "$out"
    local result_dir
    result_dir=$(jq -r '.packages[0].result_dir' "$out")
    rm -f "$out"

    local log
    log="$result_dir/build.log"
    if ! grep -q "CRBS_RPMBUILD_PHASE" "$log"; then
        error "CRBS_RPMBUILD_PHASE missing from build.log (instrumentation must be unconditional)"
        return 1
    fi
    if grep -q "CRBS_SPEC_HOOK" "$log"; then
        error "CRBS_SPEC_HOOK found in build.log without [hooks.spec] config"
        return 1
    fi

    # profile.json 恒写
    if [[ ! -f "$result_dir/profile.json" ]]; then
        error "profile.json missing: $result_dir/profile.json"
        return 1
    fi

    info "unconditional instrumentation present, no hook injection without [hooks.spec]"
}

# ─── main ──────────────────────────────────────────────────────

main() {
    setup
    run_test "profile subphases" test_profile_subphases
    run_test "spec hooks" test_spec_hooks
    run_test "no hook injection without hooks" test_no_hook_injection_without_hooks_config

    echo ""
    if [[ "$FAIL" -eq 0 ]]; then
        info "All $PASS tests passed"
        exit 0
    else
        error "$FAIL failed, $PASS passed"
        exit 1
    fi
}

main "$@"
