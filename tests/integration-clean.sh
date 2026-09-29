#!/bin/bash
# CRBS clean 集成测试
# 包含：clean 命令正确删除产品目录。
# 运行: sudo ./tests/integration-clean.sh [fedora-clean|other-product]

set -euo pipefail

# shellcheck source=lib/integration.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration.sh"

test_clean_removes_product() {
    local product="${1:-fedora-clean}"
    # clean 非 TTY 且无 --yes 直接拒绝执行（cmd/confirm.rs），脚本必须显式放行。
    $CRBS clean "$product" --yes
    # 产品根目录默认在 /var/lib/crbs/{product}
    if [[ -d "/var/lib/crbs/$product" ]]; then
        error "Product dir still exists after clean"
        return 1
    fi
}

list_tests() {
    echo "Available tests in integration-clean.sh:"
    echo "  clean_removes_product [product]"
}

main() {
    if [[ "${1:-}" == "--list" || "${1:-}" == "-l" || "${1:-}" == "help" ]]; then
        list_tests
        exit 0
    fi

    if [[ "$EUID" -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi

    setup

    run_test "clean_removes_product" test_clean_removes_product "${1:-fedora-clean}"

    report_results
}

main "$@"
