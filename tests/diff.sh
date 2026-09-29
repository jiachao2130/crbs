#!/bin/bash
# crbs diff 集成测试
#
# 验证：
#   1. crbs diff <id1> <id2> --format json 输出结构正确
#   2. crbs diff <id1> <id2> 文本输出包含预期段落
#
# 插桩无条件执行，diff 的 profile 对比数据恒可用。
#
# 运行: sudo ./tests/diff.sh
# 也可指定 backend: sudo BACKEND=nspawn ./tests/diff.sh

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

build_hello() {
    local out
    out=$(mktemp)
    $CRBS build "$SRPM" --product "$PRODUCT" --format json --backend "${BACKEND:-chroot}" > "$out"
    jq -r '.packages[0].build_id' "$out"
    rm -f "$out"
}

# ─── tests ─────────────────────────────────────────────────────

test_diff_json() {
    info "Building hello twice for diff..."
    local id1 id2
    id1=$(build_hello)
    id2=$(build_hello)

    if [[ -z "$id1" || "$id1" == "null" || -z "$id2" || "$id2" == "null" ]]; then
        error "failed to get build ids"
        return 1
    fi

    info "Running: crbs diff $id1 $id2 --format json"
    local out
    out=$(mktemp)
    $CRBS diff "$id1" "$id2" --format json > "$out"

    for key in command left right metadata rpms srpms packages profile; do
        if ! jq -e --arg key "$key" '.[$key]' "$out" >/dev/null; then
            error "missing json key: $key"
            rm -f "$out"
            return 1
        fi
    done

    if [[ $(jq -r '.command' "$out") != "diff" ]]; then
        error "command field is not 'diff'"
        rm -f "$out"
        return 1
    fi

    # 两次相同构建：RPM/SRPM 文件名应完全一致，无新增/删除
    for section in rpms srpms; do
        local added removed unchanged
        added=$(jq -r ".${section}.added | length" "$out")
        removed=$(jq -r ".${section}.removed | length" "$out")
        unchanged=$(jq -r ".${section}.unchanged" "$out")
        if [[ "$added" -ne 0 || "$removed" -ne 0 || "$unchanged" -ne 1 ]]; then
            error "unexpected $section summary: added=$added removed=$removed unchanged=$unchanged"
            rm -f "$out"
            return 1
        fi
    done

    # 依赖包应完全一致
    local pkg_diff_len
    pkg_diff_len=$(jq -r '.packages | length' "$out")
    if [[ "$pkg_diff_len" -ne 0 ]]; then
        error "expected identical package list, got $pkg_diff_len diffs"
        rm -f "$out"
        return 1
    fi

    # profile 应非空且包含合理的 total/delta
    if [[ $(jq -r '.profile' "$out") == "null" ]]; then
        error "profile section is null"
        rm -f "$out"
        return 1
    fi
    local left_total right_total
    left_total=$(jq -r '.profile.left_total' "$out")
    right_total=$(jq -r '.profile.right_total' "$out")
    if ! [[ "$left_total" =~ ^[0-9]+(\.[0-9]+)?$ && "$right_total" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        error "invalid profile totals: left=$left_total right=$right_total"
        rm -f "$out"
        return 1
    fi

    rm -f "$out"
    info "json diff output looks good"
}

test_diff_text() {
    info "Building hello twice for diff (text)..."
    local id1 id2
    id1=$(build_hello)
    id2=$(build_hello)

    info "Running: crbs diff $id1 $id2"
    local out
    out=$(mktemp)
    $CRBS diff "$id1" "$id2" > "$out"

    for marker in "Diff:" "Metadata:" "RPM files:"; do
        if ! grep -q "$marker" "$out"; then
            error "missing text marker: $marker"
            rm -f "$out"
            return 1
        fi
    done

    rm -f "$out"
    info "text diff output looks good"
}

# ─── main ──────────────────────────────────────────────────────

main() {
    setup
    run_test "diff json" test_diff_json
    run_test "diff text" test_diff_text

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
