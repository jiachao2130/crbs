#!/bin/bash
# CRBS 本地 daemon 集成测试
# 运行: sudo ./tests/local-daemon.sh [test_name_or_prefix ...]
#
# 测试本地 daemon 的自动发现/启动、start/stop/status、多 SRPM 批量提交、
# detach/attach 以及 stale pidfile 清理。使用独立 run_dir 和配置目录，
# 避免干扰系统可能正在运行的 daemon。

set -euo pipefail

# shellcheck source=lib/integration.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration.sh"

CRBS_SERVER=${CRBS_SERVER:-"$(dirname "$CRBS")/crbs-server"}

# 每个测试独立的临时配置目录
TEST_CONFIG_DIR=""
TEST_RUN_DIR=""

setup_test_config() {
    TEST_CONFIG_DIR="$(mktemp -d /tmp/crbs-local-daemon-test-XXXXXX)"
    TEST_RUN_DIR="$TEST_CONFIG_DIR/run"
    mkdir -p "$TEST_CONFIG_DIR/products"

    # crbs.toml：复用系统已有的 /var/lib/crbs base_os，避免重复 init
    cat > "$TEST_CONFIG_DIR/crbs.toml" <<EOF
crbs_root = "/var/lib/crbs"
result_dir = "/var/lib/crbs/results"
shared_layers_dir = "/var/lib/crbs/shared_layers"
EOF

    # server.toml：使用独立 run_dir
    cat > "$TEST_CONFIG_DIR/server.toml" <<EOF
[local]
enable = true
run_dir = "$TEST_RUN_DIR"
idle_timeout_secs = 300
EOF

    # 复用系统已配置好的 fedora 产品配置
    if [[ -f /etc/crbs/products/fedora.toml ]]; then
        cp /etc/crbs/products/fedora.toml "$TEST_CONFIG_DIR/products/fedora.toml"
    else
        error "Missing /etc/crbs/products/fedora.toml; run integration-local.sh setup first"
        return 1
    fi
}

teardown_test_config() {
    if [[ -n "${TEST_CONFIG_DIR:-}" && -d "$TEST_CONFIG_DIR" ]]; then
        # 停止可能残留的 daemon
        CRBS_CONFIG_DIR="$TEST_CONFIG_DIR" "$CRBS_SERVER" local stop >/dev/null 2>&1 || true
        rm -rf "$TEST_CONFIG_DIR"
    fi
}

run_with_config() {
    CRBS_CONFIG_DIR="$TEST_CONFIG_DIR" "$@"
}

test_start_stop_status() {
    run_with_config "$CRBS_SERVER" local start
    assert_file_exists "$TEST_RUN_DIR/crbs-server.pid"
    assert_file_exists "$TEST_RUN_DIR/crbs-server.port"

    local status_output
    status_output=$(run_with_config "$CRBS_SERVER" local status)
    if ! echo "$status_output" | grep -q "is running"; then
        error "Expected daemon to be running: $status_output"
        return 1
    fi

    run_with_config "$CRBS_SERVER" local stop
    if [[ -f "$TEST_RUN_DIR/crbs-server.pid" ]]; then
        error "pidfile should be removed after stop"
        return 1
    fi
    if [[ -f "$TEST_RUN_DIR/crbs-server.port" ]]; then
        error "portfile should be removed after stop"
        return 1
    fi
}

test_build_uses_local_daemon() {
    run_with_config "$CRBS_SERVER" local start
    assert_file_exists "$TEST_RUN_DIR/crbs-server.pid"

    local backend="${BACKEND:-chroot}"
    run_with_config "$CRBS" build --daemon "$SRPM" --product fedora --stage bb --backend "$backend"

    # 构建完成后 daemon 应该仍在运行
    assert_file_exists "$TEST_RUN_DIR/crbs-server.pid"
}

test_detach_attach() {
    run_with_config "$CRBS_SERVER" local start

    local backend="${BACKEND:-chroot}"
    local output
    output=$(run_with_config "$CRBS" build --daemon "$SRPM" --product fedora --stage bb --backend "$backend" --detach --format json)
    local build_id
    build_id=$(echo "$output" | python3 -c 'import json,sys; print(json.load(sys.stdin)["builds"][0]["build_id"])')
    if [[ -z "$build_id" ]]; then
        error "Failed to extract build_id from detach output"
        return 1
    fi
    info "Detached build_id: $build_id"

    run_with_config "$CRBS" build --daemon --attach "$build_id" --backend "$backend"
}

test_stale_pidfile_cleanup() {
    mkdir -p "$TEST_RUN_DIR"
    echo "999999" > "$TEST_RUN_DIR/crbs-server.pid"
    echo "12345" > "$TEST_RUN_DIR/crbs-server.port"
    echo "" > "$TEST_RUN_DIR/crbs-server.lock"

    # 客户端通过 --daemon 触发 ensure_running，发现 stale pidfile 时会自动清理并启动新 daemon
    local backend="${BACKEND:-chroot}"
    run_with_config "$CRBS" build --daemon "$SRPM" --product fedora --stage bb --backend "$backend"

    # 验证 stale 文件已被新 daemon 覆盖/清理
    local pid
    pid=$(cat "$TEST_RUN_DIR/crbs-server.pid")
    if [[ "$pid" == "999999" ]]; then
        error "Stale pidfile was not cleaned up"
        return 1
    fi
    assert_file_exists "$TEST_RUN_DIR/crbs-server.port"
}

test_multi_srpm_batch() {
    run_with_config "$CRBS_SERVER" local start

    # 用同一个 SRPM 复制一份作为第二个输入，验证批量提交不报错
    local srpm2
    srpm2="$TEST_CONFIG_DIR/hello-copy.src.rpm"
    cp "$SRPM" "$srpm2"

    local backend="${BACKEND:-chroot}"
    local output
    output=$(run_with_config "$CRBS" build --daemon "$SRPM" "$srpm2" --product fedora --stage bb --backend "$backend" --detach --format json)
    local count
    count=$(echo "$output" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["builds"]))')
    if [[ "$count" != "2" ]]; then
        error "Expected 2 build ids from multi-srpm detach, got $count"
        return 1
    fi
    info "Multi-SRPM detach returned $count build ids"
}

list_tests() {
    echo "Available tests in local-daemon.sh:"
    echo "  start_stop_status"
    echo "  build_uses_local_daemon"
    echo "  detach_attach"
    echo "  stale_pidfile_cleanup"
    echo "  multi_srpm_batch"
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
    setup_test_config
    trap teardown_test_config EXIT

    if should_run "start_stop_status" "$@"; then
        run_test "start_stop_status" test_start_stop_status
    fi
    if should_run "build_uses_local_daemon" "$@"; then
        run_test "build_uses_local_daemon_${BACKEND:-chroot}" test_build_uses_local_daemon
    fi
    if should_run "detach_attach" "$@"; then
        run_test "detach_attach_${BACKEND:-chroot}" test_detach_attach
    fi
    if should_run "stale_pidfile_cleanup" "$@"; then
        run_test "stale_pidfile_cleanup_${BACKEND:-chroot}" test_stale_pidfile_cleanup
    fi
    if should_run "multi_srpm_batch" "$@"; then
        run_test "multi_srpm_batch_${BACKEND:-chroot}" test_multi_srpm_batch
    fi

    report_results
}

main "$@"
