#!/bin/bash
# crbs server API 集成测试
# 测试所有关键端点（含 token 认证）。
# 契约：POST /builds 响应无 id 键（取 ids[0]）；GET /artifacts 不返回
# result_dir；构建 ID 为 i64，服务端无短 ID/UUID 路由，使用数字 ID 路由。
# 需要 root/sudo 以生成 API token 并启动 server。
set -euo pipefail

CRBS=${CRBS:-/usr/local/bin/crbs}
CRBS_SERVER=${CRBS_SERVER:-/usr/local/bin/crbs-server}
PORT=${CRBS_SERVER_PORT:-9090}
BASE="http://127.0.0.1:${PORT}"
PRODUCT="fedora"

AUTH=()
SERVER_PID=""
TMP_CONFIG_DIR=""

PASS=0; FAIL=0
RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
info() { echo -e "${GREEN}[INFO]${NC} $*"; }

assert_status() {
    local expected="$1" actual="$2" msg="$3"
    if [[ "$actual" == "$expected" ]]; then
        info "PASS: $msg ($actual)"
        PASS=$((PASS+1))
    else
        echo -e "${RED}[FAIL]${NC} $msg: expected=$expected actual=$actual"
        FAIL=$((FAIL+1))
    fi
}

assert_contains() {
    local pattern="$1" body="$2" msg="$3"
    if echo "$body" | grep -q "$pattern"; then
        info "PASS: $msg"
        PASS=$((PASS+1))
    else
        echo -e "${RED}[FAIL]${NC} $msg: missing '$pattern'"
        FAIL=$((FAIL+1))
    fi
}

assert_not_contains() {
    local pattern="$1" body="$2" msg="$3"
    if ! echo "$body" | grep -q "$pattern"; then
        info "PASS: $msg"
        PASS=$((PASS+1))
    else
        echo -e "${RED}[FAIL]${NC} $msg: unexpectedly found '$pattern'"
        FAIL=$((FAIL+1))
    fi
}

# 产品管理端点（init/clean/DELETE）属于破坏性操作，需要 operator/admin 角色。
# 认证凭据全部存放在 SQLite（与 server 共用 state.db），因此这里创建一个 admin
# 用户并签发 DB token，再启动 server。
TMP_CONFIG_DIR=$(mktemp -d)
if [[ -d /etc/crbs ]]; then
    cp -r /etc/crbs/. "$TMP_CONFIG_DIR/"
fi
cat > "$TMP_CONFIG_DIR/server.toml" <<EOF
listen = "127.0.0.1:${PORT}"
allow_product_management = true
EOF

AUTH_USER="server-api-admin"
info "Creating admin user ${AUTH_USER}..."
if ! $CRBS_SERVER user add "$AUTH_USER" --role admin --config-dir "$TMP_CONFIG_DIR" >/dev/null; then
    echo -e "${RED}[FAIL]${NC} Failed to create admin user"
    rm -rf "$TMP_CONFIG_DIR"
    exit 1
fi

info "Generating API token..."
TOKEN_OUTPUT=$($CRBS_SERVER token create --user "$AUTH_USER" --name "server-api-auth-test" --config-dir "$TMP_CONFIG_DIR" 2>/dev/null)
CRBS_SERVER_TOKEN=$(echo "$TOKEN_OUTPUT" | grep '^Token: ' | sed 's/^Token: //' | tr -d '[:space:]')
if [[ -z "$CRBS_SERVER_TOKEN" ]]; then
    echo -e "${RED}[FAIL]${NC} Failed to generate API token"
    echo "$TOKEN_OUTPUT"
    rm -rf "$TMP_CONFIG_DIR"
    exit 1
fi
export CRBS_SERVER_TOKEN
AUTH=(-H "Authorization: Bearer ${CRBS_SERVER_TOKEN}")
info "Token generated: ${CRBS_SERVER_TOKEN:0:8}..."

info "Starting server with token auth..."
$CRBS_SERVER run --config-dir "$TMP_CONFIG_DIR" --listen "127.0.0.1:${PORT}" &
SERVER_PID=$!

# 等待 server 就绪
for i in $(seq 1 30); do
    if curl -sf "${BASE}/api/v1/health" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

cleanup() {
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_CONFIG_DIR"
}
trap cleanup EXIT

# 认证失败测试
R=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/api/v1/builds")
assert_status "401" "$R" "GET /builds without token returns 401"

R=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer wrong-token" "${BASE}/api/v1/builds")
assert_status "401" "$R" "GET /builds with wrong token returns 401"

# 健康检查仍无需认证
R=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/api/v1/health")
assert_status "200" "$R" "GET /health without token returns 200"

# 使用项目自带的 hello fixture
FIXTURES="$(cd "$(dirname "$0")" && pwd)/fixtures"
SRPM_DIR="$FIXTURES/hello"

# 生成 SRPM（如不存在，dist 标签随环境变化）
if ! ls "$SRPM_DIR"/hello-*.src.rpm >/dev/null 2>&1; then
    echo "Building hello SRPM..."
    (cd "$SRPM_DIR" && rpmbuild -bs --define "_srcrpmdir ." --define "_sourcedir ." hello.spec)
fi
SRPM="$(ls "$SRPM_DIR"/hello-*.src.rpm | head -1)"

poll_build() {
    local build_id="$1" max="${2:-60}"
    for i in $(seq 1 "$max"); do
        sleep 5
        R=$(curl -s "${AUTH[@]}" "${BASE}/api/v1/builds/${build_id}")
        phase=$(echo "$R" | python3 -c "import json,sys; print(json.load(sys.stdin)['phase'])" 2>/dev/null || true)
        case "$phase" in
            succeeded|failed|cancelled|timeout) break ;;
            *) info "  poll ${i}: ${phase}..." ;;
        esac
    done
    echo "$R"
}

poll_gc() {
    local task_id="$1" max="${2:-30}"
    for i in $(seq 1 "$max"); do
        sleep 2
        R=$(curl -s "${AUTH[@]}" "${BASE}/api/v1/gc/${task_id}")
        status=$(echo "$R" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])" 2>/dev/null || true)
        case "$status" in
            succeeded|failed) break ;;
            *) info "  gc poll ${i}: ${status}..." ;;
        esac
    done
    echo "$R"
}

echo "=== crbs server API tests ==="
echo "Server: $BASE"
echo ""

# 1. Health
R=$(curl -s "${AUTH[@]}" "${BASE}/api/v1/health")
assert_contains '"ok"' "$R" "GET /health"

# 2. Version
R=$(curl -s "${AUTH[@]}" "${BASE}/api/v1/version")
assert_contains '"version"' "$R" "GET /version"

# 2a. Metrics (public, detailed monitoring endpoint)
R=$(curl -s "${BASE}/api/v1/metrics")
assert_contains '"ok"' "$R" "GET /metrics status ok"
assert_contains '"concurrency"' "$R" "GET /metrics contains concurrency"
assert_contains '"queue"' "$R" "GET /metrics contains queue"
assert_contains '"disk"' "$R" "GET /metrics contains disk"
METRICS_MAX=$(echo "$R" | python3 -c "import json,sys; print(json.load(sys.stdin)['concurrency']['max'])" 2>/dev/null || echo 0)
if [[ "$METRICS_MAX" -gt 0 ]]; then
    info "PASS: /metrics concurrency.max=${METRICS_MAX}"
    PASS=$((PASS+1))
else
    echo -e "${RED}[FAIL]${NC} /metrics concurrency.max should be > 0"
    FAIL=$((FAIL+1))
fi
METRICS_DISK=$(echo "$R" | python3 -c "import json,sys; print(json.load(sys.stdin)['disk']['available_bytes'])" 2>/dev/null || echo 0)
if [[ "$METRICS_DISK" -gt 0 ]]; then
    info "PASS: /metrics disk.available_bytes=${METRICS_DISK}"
    PASS=$((PASS+1))
else
    echo -e "${RED}[FAIL]${NC} /metrics disk.available_bytes should be > 0"
    FAIL=$((FAIL+1))
fi

# 3. Products
R=$(curl -s "${AUTH[@]}" "${BASE}/api/v1/products")
assert_contains "$PRODUCT" "$R" "GET /products contains fedora"

# 4. Submit build
R=$(curl -s -X POST "${AUTH[@]}" "${BASE}/api/v1/builds" \
    -H "Content-Type: application/json" \
    -d "{\"product\":\"${PRODUCT}\",\"srpms\":[\"${SRPM}\"],\"stage\":\"bb\"}")
# 响应键为 {task_id, ids, phase, product, submitted_at}：轮询用子构建 ids[0]。
# pending 断言先于 ids 提取：提交失败时报 FAIL 而非在 python 解析处裸中止。
assert_contains '"pending"' "$R" "POST /builds returns pending"
BUILD_ID=$(echo "$R" | python3 -c "import json,sys; print(json.load(sys.stdin)['ids'][0])" 2>/dev/null)
info "  build_id=$BUILD_ID"

# 5. Poll until completed (max 5 min)
R=$(poll_build "$BUILD_ID")
assert_contains "succeeded" "$R" "Build phase is succeeded (after poll)"

# 6. List builds
R=$(curl -s "${AUTH[@]}" "${BASE}/api/v1/builds?product=${PRODUCT}&limit=1")
assert_contains "$BUILD_ID" "$R" "GET /builds lists the build"

# 7. Logs (chunked streaming from offset 0)
R=$(curl -s -N "${AUTH[@]}" "${BASE}/api/v1/builds/${BUILD_ID}/logs?offset=0")
assert_contains "CRBS_PHASE" "$R" "GET /logs returns streamed build output"

# 8. Cancel (already succeeded → 409)
R=$(curl -s -X POST "${AUTH[@]}" "${BASE}/api/v1/builds/${BUILD_ID}/cancel")
assert_contains "cannot_cancel_terminal_build" "$R" "POST /cancel on succeeded returns 409"

# 9. Path traversal rejected
R=$(curl -s -X POST "${AUTH[@]}" "${BASE}/api/v1/builds" \
    -H "Content-Type: application/json" \
    -d '{"product":"fedora","srpms":["../etc/passwd"]}')
assert_contains "validation_failed" "$R" "Path traversal returns validation_failed"

# 10. Empty srpms rejected; multiple srpms accepted
R=$(curl -s -X POST "${AUTH[@]}" "${BASE}/api/v1/builds" \
    -H "Content-Type: application/json" \
    -d '{"product":"fedora","srpms":[]}')
assert_contains "at least one SRPM" "$R" "Empty srpms returns validation_failed"

R=$(curl -s -X POST "${AUTH[@]}" "${BASE}/api/v1/builds" \
    -H "Content-Type: application/json" \
    -d "{\"product\":\"fedora\",\"srpms\":[\"${SRPM}\",\"${SRPM}\"]}")
assert_status "2" "$(echo "$R" | python3 -c "import json,sys; print(json.load(sys.stdin)['ids'].__len__())" 2>/dev/null || echo 0)" "Multiple srpms returns two ids"

# 11. Artifacts list
R=$(curl -s "${AUTH[@]}" "${BASE}/api/v1/builds/${BUILD_ID}/artifacts")
# M-1 反泄漏契约：响应不得携带服务器绝对路径 result_dir（list.rs 有显式不存在断言）。
assert_not_contains '"result_dir"' "$R" "GET /artifacts must NOT return result_dir"
assert_contains 'hello-' "$R" "GET /artifacts contains hello artifact"
ARTIFACT=$(echo "$R" | python3 -c "import json,sys; d=json.load(sys.stdin); print((d.get('rpms') or d.get('srpms') or [''])[0])" 2>/dev/null)
info "  artifact=$ARTIFACT"

# 12. Download artifact
if [[ -n "$ARTIFACT" ]]; then
    R=$(curl -s -o /dev/null -w "%{http_code}\n%{content_type}\n" \
        "${AUTH[@]}" "${BASE}/api/v1/builds/${BUILD_ID}/artifacts/download?file=${ARTIFACT}")
    http_code=$(echo "$R" | head -1)
    content_type=$(echo "$R" | tail -1)
    assert_status "200" "$http_code" "GET /artifacts/download returns 200"
    assert_contains "application/x-rpm" "$content_type" "Artifact content-type is application/x-rpm"
fi

# 13. Logs streaming / 404 / numeric ID routing
# ID 已是 i64：不存在则 404（UUID 形态连 i64 解析都过不了，不再是有效用例）。
R=$(curl -s -o /dev/null -w "%{http_code}" "${AUTH[@]}" "${BASE}/api/v1/builds/999999999/logs")
assert_status "404" "$R" "GET /logs for missing build returns 404"

# 13a. Numeric ID routing for build, logs, artifacts, profile。
# 短 ID（UUID/前缀）路由已随 i64 ID 改革移除：服务端 {id} 一律按数字精确
# 解析（AxumPath<i64>），CLI 侧 resolve_short_id 也只接受完整数字 ID。
R=$(curl -s "${AUTH[@]}" "${BASE}/api/v1/builds/${BUILD_ID}")
assert_contains '"succeeded"' "$R" "GET /builds/{id} resolves"

R=$(curl -s -o /dev/null -w "%{http_code}" -N "${AUTH[@]}" "${BASE}/api/v1/builds/${BUILD_ID}/logs?offset=0")
assert_status "200" "$R" "GET /builds/{id}/logs resolves"

R=$(curl -s -o /dev/null -w "%{http_code}" "${AUTH[@]}" "${BASE}/api/v1/builds/${BUILD_ID}/artifacts")
assert_status "200" "$R" "GET /builds/{id}/artifacts resolves"

R=$(curl -s -o /dev/null -w "%{http_code}" "${AUTH[@]}" "${BASE}/api/v1/builds/${BUILD_ID}/profile")
assert_status "200" "$R" "GET /builds/{id}/profile resolves"

# 14. GC dry-run
R=$(curl -s -X POST "${AUTH[@]}" "${BASE}/api/v1/gc" \
    -H "Content-Type: application/json" \
    -d '{"dry_run":true,"results":true}')
GC_ID=$(echo "$R" | python3 -c "import json,sys; print(json.load(sys.stdin)['task_id'])" 2>/dev/null)
assert_contains '"running"' "$R" "POST /gc returns running"
R=$(poll_gc "$GC_ID")
assert_contains '"succeeded"' "$R" "GET /gc/{id} reports succeeded"
assert_contains '"would_remove"' "$R" "GC results summary contains would_remove"

# 15. Submit stage=bs build
R=$(curl -s -X POST "${AUTH[@]}" "${BASE}/api/v1/builds" \
    -H "Content-Type: application/json" \
    -d "{\"product\":\"${PRODUCT}\",\"srpms\":[\"${SRPM}\"],\"stage\":\"bs\"}")
BS_BUILD_ID=$(echo "$R" | python3 -c "import json,sys; print(json.load(sys.stdin)['ids'][0])" 2>/dev/null)
assert_contains '"pending"' "$R" "POST /builds stage=bs returns pending"
R=$(poll_build "$BS_BUILD_ID")
assert_contains "succeeded" "$R" "stage=bs build succeeds"

# 16. diff two builds
R=$(curl -s "${AUTH[@]}" "${BASE}/api/v1/builds/${BUILD_ID}/diff?against=${BS_BUILD_ID}")
assert_contains '"left"' "$R" "GET /diff returns left"
assert_contains '"right"' "$R" "GET /diff returns right"

# 17. Crash recovery: pending build survives server restart and auto-resumes
info "Testing crash recovery..."
R=$(curl -s "${BASE}/api/v1/metrics")
PENDING=$(echo "$R" | python3 -c "import json,sys; print(json.load(sys.stdin)['queue']['pending'])" 2>/dev/null || echo 0)
if [[ "$PENDING" -ne 0 ]]; then
    echo -e "${RED}[FAIL]${NC} Crash recovery: queue not empty before test (pending=${PENDING})"
    FAIL=$((FAIL+1))
else
    # 杀掉当前 server，模拟崩溃
    kill -9 "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true

    # 重新启动一个干净的 server
    $CRBS_SERVER run --config-dir "$TMP_CONFIG_DIR" --listen "127.0.0.1:${PORT}" &
    SERVER_PID=$!
    for i in $(seq 1 30); do
        if curl -sf "${BASE}/api/v1/health" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done

    # 提交构建并立刻再次杀掉 server，尽量让任务停留在 pending
    R=$(curl -s -X POST "${AUTH[@]}" "${BASE}/api/v1/builds" \
        -H "Content-Type: application/json" \
        -d "{\"product\":\"${PRODUCT}\",\"srpms\":[\"${SRPM}\"],\"stage\":\"bb\"}")
    RECOVER_ID=$(echo "$R" | python3 -c "import json,sys; print(json.load(sys.stdin)['ids'][0])" 2>/dev/null || true)
    RECOVER_PHASE=$(echo "$R" | python3 -c "import json,sys; print(json.load(sys.stdin)['phase'])" 2>/dev/null || true)

    if [[ -n "$RECOVER_ID" && "$RECOVER_PHASE" == "pending" ]]; then
        kill -9 "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true

        # 再次启动 server：恢复调度器应自动执行遗留的 pending 任务
        $CRBS_SERVER run --config-dir "$TMP_CONFIG_DIR" --listen "127.0.0.1:${PORT}" &
        SERVER_PID=$!
        for i in $(seq 1 30); do
            if curl -sf "${BASE}/api/v1/health" >/dev/null 2>&1; then
                break
            fi
            sleep 1
        done

        R=$(poll_build "$RECOVER_ID" 60)
        assert_contains "succeeded" "$R" "Crash recovery: pending build resumes and succeeds"
    else
        echo -e "${RED}[FAIL]${NC} Crash recovery: failed to create pending build (id=${RECOVER_ID}, phase=${RECOVER_PHASE})"
        FAIL=$((FAIL+1))
    fi
fi

echo ""
if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}All ${PASS} tests PASSED${NC}"
    exit 0
else
    echo -e "${RED}${FAIL} test(s) FAILED, ${PASS} passed${NC}"
    exit 1
fi
