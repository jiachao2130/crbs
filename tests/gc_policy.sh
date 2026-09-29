#!/bin/bash
# GC policy 回归测试
# 验证配置了 result_max_count_per_pkg / package_cache_max_size_gb 后，
# `crbs gc --policy -d` 能正确识别需要清理的 result_dir 和 package_cache。
#
# 口径风险提醒：expected_policy_removals 按
# `crbs status` 的 task 计数推算超额 result_dir，而 GC 按实际 result_dir
# 计数——task:result_dir 是 1:N（多 SRPM/多 arch 任务产生多个子构建目录，
# status JSON 的 result_dir 只是其一）。当前单包单 arch fixture 下两者恰好
# 相等；一旦引入批量/多 arch 构建用例，expected 会系统性低估，需改为按
# 子构建（build 记录）计数。
#
# 运行: sudo ./tests/gc_policy.sh

set -euo pipefail

CRBS=${CRBS:-/usr/local/bin/crbs}
FIXTURES="$(cd "$(dirname "$0")" && pwd)/fixtures"
SRPM="$FIXTURES/hello/hello-1.0-1.fc44.src.rpm"
GLOBAL_CONFIG="/etc/crbs/crbs.toml"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

PASS=0
FAIL=0

info() { echo -e "${GREEN}[INFO]${NC} $*"; }
error() { echo -e "${RED}[FAIL]${NC} $*"; }

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

setup() {
    if [[ "$EUID" -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi

    info "Setup: generating SRPM if needed..."
    if [[ ! -f "$SRPM" ]]; then
        (cd "$FIXTURES/hello" && rpmbuild -bs --define "_srcrpmdir ." --define "_sourcedir ." --define "dist .fc44" hello.spec)
    fi
    [[ -f "$SRPM" ]] || { error "SRPM not found: $SRPM"; exit 1; }

    info "Setup: ensuring product config exists..."
    mkdir -p /etc/crbs/products
    if [[ ! -f "/etc/crbs/products/fedora.toml" ]]; then
        cat > "/etc/crbs/products/fedora.toml" <<EOF
product = "fedora"
base_packages = ["rpm-build", "dnf"]

ccache_enabled = true
dnf_cache_enabled = true

[[repos]]
name = "fedora"
baseurl = "https://mirrors.tuna.tsinghua.edu.cn/fedora/releases/44/Everything/x86_64/os/"
gpgcheck = false
EOF
    fi

    # 备份全局配置：mktemp 唯一化备份路径——固定名在并行跑两个 gc_policy
    # 时互相覆盖/提前恢复。
    BACKUP="$(mktemp /tmp/crbs.toml.gc_policy.XXXXXX.bak)"
    if [[ -f "$GLOBAL_CONFIG" ]]; then
        cp "$GLOBAL_CONFIG" "$BACKUP"
    fi

    restore_config() {
        if [[ -s "$BACKUP" ]]; then
            mv "$BACKUP" "$GLOBAL_CONFIG"
        else
            rm -f "$GLOBAL_CONFIG" "$BACKUP"
        fi
    }
    trap restore_config EXIT

    # 写入带 policy 的全局配置
    cat > "$GLOBAL_CONFIG" <<EOF
# 测试用 GC policy 配置
crbs_root = "/var/lib/crbs"
result_dir = "/var/lib/crbs/results"
shared_layers_dir = "/var/lib/crbs/shared_layers"

builder_user = "ccbuilder"
builder_uid = 10010
builder_group = "ccbuilder"
builder_gid = 10010

shared_layer_gc_grace_hours = 168
result_gc_grace_hours = 720

# 只保留每个包的 1 个 result_dir，用于验证 policy
result_max_count_per_pkg = 1

# 把包缓存上限压到 1GB，触发 LRU 路径（至少会进入判断逻辑）
package_cache_max_size_gb = 1

# 测试需要 package_cache 被填充
reproduce_enabled = true
EOF
}

# 按当前 status 计算 result_max_count_per_pkg=1 时应移除的 result_dir 总数
# 与 run_result_gc_standalone 保持一致：phase != building 且 completed_at 非空
expected_policy_removals() {
    $CRBS status --product fedora --all --limit 0 --format json 2>/dev/null \
        | python3 -c '
import json, sys
from collections import Counter
data = json.load(sys.stdin)
counts = Counter(
    b.get("pkg_name", "")
    for b in data
    if b.get("phase") != "building" and b.get("result_dir")
)
print(sum(c - 1 for c in counts.values() if c > 1))
' 2>/dev/null
}

# ─── tests ─────────────────────────────────────────────────────

# 为同一个包生成两个 result_dir，验证 policy 识别超量结果
test_result_count_policy() {
    # 第一次构建
    local out1="/tmp/crbs_gc_policy_build1.log"
    if ! $CRBS build "$SRPM" --product fedora --force >"$out1" 2>&1; then
        error "first build failed; log:"
        tail -30 "$out1"
        return 1
    fi

    # 第二次构建，强制产生新的 result_dir
    local out2="/tmp/crbs_gc_policy_build2.log"
    if ! $CRBS build "$SRPM" --product fedora --force >"$out2" 2>&1; then
        error "second build failed; log:"
        tail -30 "$out2"
        return 1
    fi

    local expected
    expected=$(expected_policy_removals)
    [[ "$expected" -ge 1 ]] || { error "Expected at least 1 excess result, got $expected"; return 1; }

    # dry-run policy GC，应识别出与 status 计算一致的 result_dir 数量
    local output
    output=$($CRBS gc --policy --product fedora --dry-run 2>/dev/null)
    echo "$output"

    if echo "$output" | grep -q "Result dirs: $expected would be removed"; then
        return 0
    else
        error "Expected 'Result dirs: $expected would be removed' in policy dry-run output"
        return 1
    fi
}

# package_cache policy 至少被触发，命令不崩溃且输出包含 package_cache 摘要
test_package_cache_policy_path() {
    local output
    output=$($CRBS gc --policy --product fedora --dry-run 2>/dev/null)
    echo "$output"

    if echo "$output" | grep -q "Package cache:"; then
        return 0
    else
        error "Expected 'Package cache:' summary in policy dry-run output"
        return 1
    fi
}

# ─── main ──────────────────────────────────────────────────────

setup
run_test "result count policy identifies excess results" test_result_count_policy
run_test "package cache policy path produces summary" test_package_cache_policy_path

echo ""
info "Results: PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]]
