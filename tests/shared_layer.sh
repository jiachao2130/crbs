#!/bin/bash
# shared_layer 集成测试
#
# 验证：
#   1. shared_layer = true 时，带 BuildRequires 的 SRPM 能成功构建
#   2. 第二次构建同一依赖集合会命中 SharedLayer cache
#
# 运行: sudo ./tests/shared_layer.sh
# 也可指定 backend: sudo BACKEND=nspawn ./tests/shared_layer.sh

set -euo pipefail

CRBS=${CRBS:-/usr/local/bin/crbs}
PRODUCT="fedora-shared"
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
    info "Setup: generating SRPM with BuildRequires..."
    TMPDIR=$(mktemp -d)
    SPECDIR="$TMPDIR/SPECS"
    mkdir -p "$SPECDIR"
    cat > "$SPECDIR/crbs-shared-test.spec" <<'EOF'
Name:           crbs-shared-test
Version:        1.0
Release:        1%{?dist}
Summary:        Shared layer integration test package
License:        MIT
BuildArch:      noarch

BuildRequires:  gcc

%description
Dummy package used by crbs shared_layer integration test.

%prep
%build
%install
mkdir -p %{buildroot}/usr/share/crbs-shared-test
echo ok > %{buildroot}/usr/share/crbs-shared-test/status

%files
/usr/share/crbs-shared-test/status
EOF
    rpmbuild -bs --define "_srcrpmdir $TMPDIR" --define "_sourcedir $TMPDIR" "$SPECDIR/crbs-shared-test.spec" >/dev/null
    SRPM=$(find "$TMPDIR" -name '*.src.rpm' | head -1)

    info "Setup: ensuring product config exists..."
    mkdir -p /etc/crbs/products
    cat > "/etc/crbs/products/$PRODUCT.toml" <<EOF
product = "fedora"
base_packages = ["rpm-build", "dnf"]
shared_layer = true

[[repos]]
name = "fedora"
baseurl = "$REPO_URL"
gpgcheck = false
EOF

    local base_os="/var/lib/crbs/$PRODUCT/base"
    if [[ ! -d "$base_os" && -n "${SKIP_IF_NO_NETWORK:-}" ]]; then
        warn "base_os missing and SKIP_IF_NO_NETWORK is set; skipping integration tests"
        exit 0
    fi

    $CRBS init "$PRODUCT" 2>/dev/null || true
}

# ─── helpers ───────────────────────────────────────────────────

build_and_capture() {
    local out err
    out=$(mktemp)
    err=$(mktemp)
    $CRBS build "$SRPM" --product "$PRODUCT" --format json --backend "${BACKEND:-chroot}" > "$out" 2> "$err"
    jq -r '.packages[0].build_id' "$out"
    cat "$err"
    rm -f "$out" "$err"
}

# ─── tests ─────────────────────────────────────────────────────

test_shared_layer_create_and_hit() {
    info "First build: should create SharedLayer..."
    local out1 err1 id1
    out1=$(mktemp)
    err1=$(mktemp)
    $CRBS build "$SRPM" --product "$PRODUCT" --format json --backend "${BACKEND:-chroot}" > "$out1" 2> "$err1"
    id1=$(jq -r '.packages[0].build_id' "$out1")
    if [[ -z "$id1" || "$id1" == "null" ]]; then
        error "first build did not produce build_id"
        cat "$err1" >&2
        rm -f "$out1" "$err1"
        return 1
    fi
    if ! grep -q "SharedLayer" "$err1"; then
        error "first build did not mention SharedLayer"
        cat "$err1" >&2
        rm -f "$out1" "$err1"
        return 1
    fi
    rm -f "$out1" "$err1"
    info "first build succeeded (id=$id1)"

    info "Second build: should hit SharedLayer cache..."
    local out2 err2 id2
    out2=$(mktemp)
    err2=$(mktemp)
    $CRBS build "$SRPM" --product "$PRODUCT" --format json --backend "${BACKEND:-chroot}" > "$out2" 2> "$err2"
    id2=$(jq -r '.packages[0].build_id' "$out2")
    if [[ -z "$id2" || "$id2" == "null" ]]; then
        error "second build did not produce build_id"
        cat "$err2" >&2
        rm -f "$out2" "$err2"
        return 1
    fi
    if ! grep -q "SharedLayer cache hit" "$err2"; then
        error "second build did not hit SharedLayer cache"
        cat "$err2" >&2
        rm -f "$out2" "$err2"
        return 1
    fi
    rm -f "$out2" "$err2"
    info "second build hit SharedLayer cache (id=$id2)"
}

test_shared_layer_concurrent() {
    info "Running two concurrent shared_layer builds..."
    local out1 err1 out2 err2 id1 id2
    out1=$(mktemp); err1=$(mktemp)
    out2=$(mktemp); err2=$(mktemp)

    $CRBS build "$SRPM" --product "$PRODUCT" --format json --backend "${BACKEND:-chroot}" > "$out1" 2> "$err1" &
    local pid1=$!
    $CRBS build "$SRPM" --product "$PRODUCT" --format json --backend "${BACKEND:-chroot}" > "$out2" 2> "$err2" &
    local pid2=$!

    if ! wait "$pid1"; then
        error "concurrent build 1 failed"
        cat "$err1" >&2
        rm -f "$out1" "$err1" "$out2" "$err2"
        return 1
    fi
    if ! wait "$pid2"; then
        error "concurrent build 2 failed"
        cat "$err2" >&2
        rm -f "$out1" "$err1" "$out2" "$err2"
        return 1
    fi

    id1=$(jq -r '.packages[0].build_id' "$out1")
    id2=$(jq -r '.packages[0].build_id' "$out2")
    if [[ -z "$id1" || "$id1" == "null" || -z "$id2" || "$id2" == "null" ]]; then
        error "concurrent builds did not produce build ids"
        rm -f "$out1" "$err1" "$out2" "$err2"
        return 1
    fi
    if [[ "$id1" == "$id2" ]]; then
        error "concurrent builds produced the same build id"
        rm -f "$out1" "$err1" "$out2" "$err2"
        return 1
    fi

    if ! grep -q "SharedLayer" "$err1" || ! grep -q "SharedLayer" "$err2"; then
        error "concurrent builds did not mention SharedLayer"
        rm -f "$out1" "$err1" "$out2" "$err2"
        return 1
    fi
    if ! grep -q "SharedLayer cache hit" "$err1" && ! grep -q "SharedLayer cache hit" "$err2"; then
        error "neither concurrent build hit SharedLayer cache"
        rm -f "$out1" "$err1" "$out2" "$err2"
        return 1
    fi

    rm -f "$out1" "$err1" "$out2" "$err2"
    info "concurrent shared_layer builds succeeded (id1=$id1, id2=$id2)"
}

# ─── cleanup ───────────────────────────────────────────────────

cleanup() {
    if [[ -n "${TMPDIR:-}" && -d "$TMPDIR" ]]; then
        rm -rf "$TMPDIR"
    fi
}
trap cleanup EXIT

# ─── main ──────────────────────────────────────────────────────

test_shared_layer_staleness_rebuild() {
    info "Testing shared_layer staleness rebuild (TTL=1s)..."
    local stale_product="fedora-shared-stale"

    cat > "/etc/crbs/products/$stale_product.toml" <<EOF
product = "fedora"
base_packages = ["rpm-build", "dnf"]
shared_layer = true
shared_layer_staleness = "1s"

[[repos]]
name = "fedora"
baseurl = "$REPO_URL"
gpgcheck = false
EOF

    local base_os="/var/lib/crbs/$stale_product/base"
    if [[ ! -d "$base_os" && -n "${SKIP_IF_NO_NETWORK:-}" ]]; then
        warn "base_os missing for stale product and SKIP_IF_NO_NETWORK is set; skipping"
        return 0
    fi
    $CRBS init "$stale_product" 2>/dev/null || true

    local out1 err1 id1
    out1=$(mktemp); err1=$(mktemp)
    $CRBS build "$SRPM" --product "$stale_product" --format json --backend "${BACKEND:-chroot}" > "$out1" 2> "$err1"
    id1=$(jq -r '.packages[0].build_id' "$out1")
    if [[ -z "$id1" || "$id1" == "null" ]]; then
        error "first stale build did not produce build_id"
        cat "$err1" >&2
        rm -f "$out1" "$err1"
        return 1
    fi
    if ! grep -q "Creating SharedLayer" "$err1"; then
        error "first stale build did not create SharedLayer"
        cat "$err1" >&2
        rm -f "$out1" "$err1"
        return 1
    fi
    rm -f "$out1" "$err1"
    info "first stale build created layer (id=$id1)"

    info "Waiting 2s for TTL to elapse..."
    sleep 2

    local out2 err2 id2
    out2=$(mktemp); err2=$(mktemp)
    $CRBS build "$SRPM" --product "$stale_product" --format json --backend "${BACKEND:-chroot}" > "$out2" 2> "$err2"
    id2=$(jq -r '.packages[0].build_id' "$out2")
    if [[ -z "$id2" || "$id2" == "null" ]]; then
        error "second stale build did not produce build_id"
        cat "$err2" >&2
        rm -f "$out2" "$err2"
        return 1
    fi
    if grep -q "SharedLayer cache hit" "$err2"; then
        error "stale SharedLayer was reused without rebuild"
        rm -f "$out2" "$err2"
        return 1
    fi
    if ! grep -q "Creating SharedLayer" "$err2"; then
        error "stale SharedLayer was not rebuilt"
        cat "$err2" >&2
        rm -f "$out2" "$err2"
        return 1
    fi
    rm -f "$out2" "$err2"
    info "stale SharedLayer rebuilt (id=$id2)"
}

main() {
    setup
    run_test "shared_layer create and cache hit" test_shared_layer_create_and_hit
    run_test "shared_layer concurrent builds" test_shared_layer_concurrent
    if [[ -n "${STALENESS_TEST:-}" ]]; then
        run_test "shared_layer staleness rebuild" test_shared_layer_staleness_rebuild
    fi

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
