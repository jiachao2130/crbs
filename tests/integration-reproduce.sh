#!/bin/bash
# CRBS reproduce 集成测试
# 包含：build + reproduce 成功、缓存缺失时 reproduce 按 URL 回退成功
# （engine/reproduce.rs）。
# 运行: sudo ./tests/integration-reproduce.sh [test_name_or_prefix ...]

set -euo pipefail

# shellcheck source=lib/integration.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration.sh"

test_build_and_reproduce() {
    local backend="${BACKEND:-chroot}"
    $CRBS build "$SRPM" --product fedora --stage bb --backend "$backend"

    local build_id
    build_id="$(latest_build_id)"
    if [[ -z "$build_id" ]]; then
        error "Failed to get latest build id"
        return 1
    fi
    info "Reproducing build $build_id"

    if ! $CRBS build --product fedora --reproduce "$build_id" --backend "$backend"; then
        error "Reproduce build failed"
        return 1
    fi

    # 验证新构建的 build_packages.json 中 URL 非空
    local new_result_dir
    new_result_dir="$(latest_result_dir)"
    if [[ -z "$new_result_dir" ]]; then
        error "No result_dir for reproduce build"
        return 1
    fi
    local url_count
    url_count="$(python3 -c "import json; data=json.load(open('${new_result_dir}/build_packages.json')); print(sum(1 for p in data if p.get('url')))" 2>/dev/null || echo 0)"
    if [[ "$url_count" -eq 0 ]]; then
        error "No package URLs preserved in reproduce build"
        return 1
    fi
    info "Reproduce build preserved $url_count package URL(s)"
}

test_reproduce_cache_miss_falls_back_to_url() {
    local backend="${BACKEND:-chroot}"
    $CRBS build "$SRPM" --product fedora --stage bb --backend "$backend"

    local build_id
    build_id="$(latest_build_id)"
    if [[ -z "$build_id" ]]; then
        error "Failed to get latest build id"
        return 1
    fi

    # 删除缓存中的第一个有 sha256 的包（包缓存布局
    # {crbs_root}/cache/packages/{sha:0:2}/{sha}；crbs_root 已由共享
    # fixture pin 为 CRBS_TEST_ROOT——P11 后引擎默认根是
    # /var/lib/crbs-engine，不 pin 时删除路径会落在不存在位置静默 no-op，
    # 本用例退化为空转）。
    local result_dir
    result_dir="$(latest_result_dir)"
    local sha
    sha="$(python3 -c "import json; data=json.load(open('${result_dir}/build_packages.json')); print(next((p['sha256'] for p in data if p.get('sha256')), ''))" 2>/dev/null)"
    if [[ -z "$sha" ]]; then
        error "No package with sha256 found to delete"
        return 1
    fi
    local cache_dir="${CRBS_TEST_ROOT}/cache/packages/${sha:0:2}/${sha}"
    info "Removing cache dir $cache_dir to simulate cache miss"
    # 目录必须真实存在：rm -rf 打在不存在路径上是静默 no-op，用例会空转
    # 通过（缓存本来就在，谈不上 miss 后的 URL 回退）。
    if [[ ! -d "$cache_dir" ]]; then
        error "Cache dir $cache_dir does not exist before deletion (crbs_root pin drift?)"
        return 1
    fi
    rm -rf "$cache_dir"

    # 现行语义（engine/reproduce.rs）：恢复 cache-first，miss 时按
    # build_packages.json 记录的 url 回退下载——缓存缺失不应导致失败。
    if ! $CRBS build --product fedora --reproduce "$build_id" --backend "$backend"; then
        error "Reproduce should succeed via URL fallback on cache miss"
        return 1
    fi
    info "Reproduce succeeded on cache miss via URL fallback"
}

list_tests() {
    echo "Available tests in integration-reproduce.sh:"
    echo "  build_and_reproduce"
    echo "  reproduce_cache_miss_falls_back_to_url"
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

    if should_run "build_and_reproduce_${BACKEND:-chroot}" "$@"; then
        run_test "build_and_reproduce_${BACKEND:-chroot}" test_build_and_reproduce
    fi
    if should_run "reproduce_cache_miss_falls_back_to_url_${BACKEND:-chroot}" "$@"; then
        run_test "reproduce_cache_miss_falls_back_to_url_${BACKEND:-chroot}" test_reproduce_cache_miss_falls_back_to_url
    fi

    report_results
}

main "$@"
