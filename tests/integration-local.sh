#!/bin/bash
# CRBS 本地构建集成测试
# 包含：单包成功构建、shell exit 0、--follow-logs 行为。
# 运行: sudo ./tests/integration-local.sh [test_name_or_prefix ...]

set -euo pipefail

# shellcheck source=lib/integration.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration.sh"

test_single_build_success() {
    local backend="${BACKEND:-chroot}"
    $CRBS build "$SRPM" --product fedora --stage bb --backend "$backend"

    # 找最新的结果目录（避免依赖 latest 软链接）
    local result_dir
    result_dir="$(ls -td /var/lib/crbs/results/fedora/hello-1.0-1.fc44/*/ 2>/dev/null | head -1)"
    if [[ -z "$result_dir" ]]; then
        error "No result directory found"
        return 1
    fi
    # 动态检查是否存在任意二进制 RPM（dist 标签可能随配置变化）
    local rpm_file
    rpm_file="$(find "${result_dir}RPMS" -name '*.rpm' -not -name '*.src.rpm' | head -1)"
    if [[ -z "$rpm_file" ]]; then
        error "No binary RPM found in ${result_dir}RPMS/"
        return 1
    fi
    info "Found binary RPM: $rpm_file"
}

test_shell_exit_zero() {
    local backend="${BACKEND:-chroot}"
    echo "exit 0" | $CRBS shell fedora -c "exit 0" --backend "$backend"
}

test_shell_bind() {
    local backend="${BACKEND:-chroot}"
    local tmpdir
    tmpdir=$(mktemp -d)
    chmod 755 "$tmpdir"
    echo "hello-bind" > "$tmpdir/from-host"
    chmod 644 "$tmpdir/from-host"

    # 显式容器路径，默认只读
    if ! $CRBS shell fedora --bind "$tmpdir:/mnt/hostbind" -c "cat /mnt/hostbind/from-host" --backend "$backend" 2>/dev/null | grep -q "hello-bind"; then
        error "--bind did not expose host file in container (read-only explicit path)"
        rm -rf "$tmpdir"
        return 1
    fi
    info "--bind read-only with explicit container path works"

    # 显式容器路径，可写
    chmod 777 "$tmpdir"
    if ! $CRBS shell fedora --bind "$tmpdir:/mnt/hostbind-rw:rw" -c "echo written > /mnt/hostbind-rw/written && cat /mnt/hostbind-rw/written" --backend "$backend" 2>/dev/null | grep -q "written"; then
        error "--bind :rw did not allow write with explicit container path"
        rm -rf "$tmpdir"
        return 1
    fi
    info "--bind read-write with explicit container path works"

    rm -rf "$tmpdir"
}

test_local_follow_logs() {
    local backend="${BACKEND:-chroot}"

    # 默认 text 模式不应输出 rpmbuild 日志内容
    local default_output
    default_output=$($CRBS build "$SRPM" --product fedora --stage bb --backend "$backend" 2>/dev/null)
    if echo "$default_output" | grep -q "CRBS_PHASE"; then
        error "Default local build should not stream build log"
        return 1
    fi
    if ! echo "$default_output" | grep -q "SUCCEEDED"; then
        error "Default local build did not report success"
        return 1
    fi
    info "Default local build shows status-only output"

    # --follow-logs 应输出 build.log 内容（含 CRBS_PHASE 标记）
    local follow_output
    follow_output=$($CRBS build "$SRPM" --product fedora --stage bb --backend "$backend" --follow-logs 2>/dev/null)
    if ! echo "$follow_output" | grep -q "CRBS_PHASE"; then
        error "Local --follow-logs should stream build log with CRBS_PHASE markers"
        return 1
    fi
    if ! echo "$follow_output" | grep -q "SUCCEEDED"; then
        error "Local --follow-logs did not report success"
        return 1
    fi
    info "Local --follow-logs streams build log"
}

list_tests() {
    echo "Available tests in integration-local.sh:"
    echo "  single_build_success"
    echo "  shell_exit_zero"
    echo "  shell_bind"
    echo "  local_follow_logs"
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

    if should_run "single_build_success_${BACKEND:-chroot}" "$@"; then
        run_test "single_build_success_${BACKEND:-chroot}" test_single_build_success
    fi
    if should_run "shell_exit_zero_${BACKEND:-chroot}" "$@"; then
        run_test "shell_exit_zero_${BACKEND:-chroot}" test_shell_exit_zero
    fi
    if should_run "shell_bind_${BACKEND:-chroot}" "$@"; then
        run_test "shell_bind_${BACKEND:-chroot}" test_shell_bind
    fi
    if should_run "local_follow_logs_${BACKEND:-chroot}" "$@"; then
        run_test "local_follow_logs_${BACKEND:-chroot}" test_local_follow_logs
    fi

    report_results
}

main "$@"
