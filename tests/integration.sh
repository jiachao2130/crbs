#!/bin/bash
# CRBS 端到端集成测试主入口
# 自动运行所有 integration-*.sh 子测试，也支持按 suite 筛选。
# 运行:
#   sudo ./tests/integration.sh                  # 全量
#   sudo ./tests/integration.sh local            # 只跑本地构建测试
#   sudo ./tests/integration.sh reproduce        # 只跑 reproduce 测试
#   sudo ./tests/integration.sh clean            # 只跑 clean 测试
#   ./tests/integration.sh --list                # 列出所有可用 suite（无需 root）
# 单个用例筛选请直接运行对应子文件，如:
#   sudo ./tests/integration-local.sh single_build_success

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[FAIL]${NC} $*"; }

# 所有子测试文件，按依赖/执行顺序排列。
INTEGRATION_FILES=(
    "integration-local.sh"
    "integration-local-daemon.sh"
    "integration-reproduce.sh"
    "integration-clean.sh"
)

list_all_tests() {
    echo "Available integration test suites:"
    for f in "${INTEGRATION_FILES[@]}"; do
        local short_name="${f%.sh}"
        short_name="${short_name#integration-}"
        echo "  $short_name  ($f)"
    done
    echo ""
    echo "For per-test selection run the suite file directly:"
    for f in "${INTEGRATION_FILES[@]}"; do
        echo "  sudo ./tests/$f --list"
    done
    echo ""
    echo "Usage: $0 [suite_name_or_prefix ...]"
    echo "Examples:"
    echo "  $0                          # run all suites"
    echo "  $0 local                    # run integration-local.sh only"
    echo "  $0 reproduce                # run integration-reproduce.sh only"
}

# 判断某个测试文件是否应该执行：无参数时全量；参数匹配 suite 短名/全名前缀。
should_run_file() {
    local file="$1"
    local suite_name="${file%.sh}"
    local short_name="${suite_name#integration-}"
    shift
    if [[ $# -eq 0 ]]; then
        return 0
    fi
    for pattern in "$@"; do
        if [[ "$short_name" == "$pattern"* || "$suite_name" == "$pattern"* || "integration-$short_name" == "$pattern"* ]]; then
            return 0
        fi
    done
    return 1
}

main() {
    if [[ "${1:-}" == "--list" || "${1:-}" == "-l" || "${1:-}" == "help" ]]; then
        list_all_tests
        exit 0
    fi

    if [[ "$EUID" -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi

    local total_pass=0
    local total_fail=0
    local ran=0

    for file in "${INTEGRATION_FILES[@]}"; do
        local path="$SCRIPT_DIR/$file"
        if [[ ! -x "$path" ]]; then
            warn "Skipping non-executable test file: $file"
            continue
        fi

        if ! should_run_file "$file" "$@"; then
            continue
        fi

        echo ""
        info "=========================================="
        info "Running suite: $file"
        info "=========================================="
        ran=$((ran + 1))

        local output
        output=$("$path" 2>&1) || true
        echo "$output"

        # 从子文件最后一行解析 PASS/FAIL 计数。
        local results
        results=$(echo "$output" | tail -1)
        if [[ "$results" =~ Results:\ PASS=([0-9]+)\ FAIL=([0-9]+) ]]; then
            total_pass=$((total_pass + BASH_REMATCH[1]))
            total_fail=$((total_fail + BASH_REMATCH[2]))
        fi
    done

    if [[ $ran -eq 0 ]]; then
        warn "No test suite matched the given filter"
        list_all_tests
        exit 1
    fi

    echo ""
    info "=========================================="
    info "Overall Results: PASS=$total_pass FAIL=$total_fail"
    info "=========================================="
    if [[ $total_fail -gt 0 ]]; then
        exit 1
    fi
}

main "$@"
