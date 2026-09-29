#!/bin/bash
# crbs build --remote 远程构建集成测试
# 验证 detach/attach/--follow-logs、数字 ID 路由以及产物下载。
# 契约：ID 为 i64，detach 输出无 short_id 行（status 单查按 task_id、
# attach/profile 按 build_id）；attach 默认不下载产物，需 --download。
# 需要 root/sudo 以生成 API token 并启动 server。
set -euo pipefail

CRBS=${CRBS:-/usr/local/bin/crbs}
CRBS_SERVER=${CRBS_SERVER:-/usr/local/bin/crbs-server}
PORT=${CRBS_SERVER_PORT:-9091}
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

TMP_CONFIG_DIR=$(mktemp -d)
if [[ -d /etc/crbs ]]; then
    cp -r /etc/crbs/. "$TMP_CONFIG_DIR/"
fi
cat > "$TMP_CONFIG_DIR/server.toml" <<EOF
listen = "127.0.0.1:${PORT}"
allow_product_management = true
EOF

info "Creating admin user and DB-backed token..."
$CRBS_SERVER user add remote-test --role admin --config-dir "$TMP_CONFIG_DIR" >/dev/null 2>&1
TOKEN_OUTPUT=$($CRBS_SERVER token create --user remote-test --name remote-build-test --config-dir "$TMP_CONFIG_DIR" 2>/dev/null)
CRBS_SERVER_TOKEN=$(echo "$TOKEN_OUTPUT" | grep '^Token: ' | sed 's/^Token: //' | tr -d '[:space:]')
if [[ -z "$CRBS_SERVER_TOKEN" ]]; then
    echo -e "${RED}[FAIL]${NC} Failed to create API token"
    echo "$TOKEN_OUTPUT"
    rm -rf "$TMP_CONFIG_DIR"
    exit 1
fi
export CRBS_SERVER_TOKEN
AUTH=(-H "Authorization: Bearer ${CRBS_SERVER_TOKEN}")
info "Token generated: ${CRBS_SERVER_TOKEN:0:8}..."

info "Starting server..."
$CRBS_SERVER run --config-dir "$TMP_CONFIG_DIR" --listen "127.0.0.1:${PORT}" &
SERVER_PID=$!

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

# 使用项目自带的 hello fixture
FIXTURES="$(cd "$(dirname "$0")" && pwd)/fixtures"
SRPM_DIR="$FIXTURES/hello"

if ! ls "$SRPM_DIR"/hello-*.src.rpm >/dev/null 2>&1; then
    echo "Building hello SRPM..."
    (cd "$SRPM_DIR" && rpmbuild -bs --define "_srcrpmdir ." --define "_sourcedir ." hello.spec)
fi
SRPM="$(ls "$SRPM_DIR"/hello-*.src.rpm | head -1)"

# 后续 crbs 命令都在 fixture 目录下执行，使产物下载到固定位置。
cd "$SRPM_DIR"

poll_remote_build() {
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

echo "=== crbs remote build tests ==="
echo "Server: $BASE"
echo ""

# 1. detach 提交后立即返回任务信息
# detach 输出（remote/output.rs）：顶层 `  task_id:` 行 + `    - build_id:` 条目；
# short_id 已随 i64 ID 改革移除。
info "Test: crbs build --remote --detach"
DETACH_OUTPUT=$($CRBS build "$SRPM" --product "$PRODUCT" --remote "$BASE" --token "$CRBS_SERVER_TOKEN" --detach 2>/dev/null)
assert_contains "build_id:" "$DETACH_OUTPUT" "detach output contains build_id"
DETACH_BUILD_ID=$(echo "$DETACH_OUTPUT" | grep "build_id:" | awk '{print $3}')
DETACH_TASK_ID=$(echo "$DETACH_OUTPUT" | grep "^  task_id:" | awk '{print $2}')
info "  build_id=$DETACH_BUILD_ID task_id=$DETACH_TASK_ID"

# 等待 detach 的构建完成
poll_remote_build "$DETACH_BUILD_ID" >/dev/null
R=$(curl -s "${AUTH[@]}" "${BASE}/api/v1/builds/${DETACH_BUILD_ID}")
assert_contains '"succeeded"' "$R" "Detached build eventually succeeds"

# 2. 用 build_id attach 并下载产物（attach 默认不下载，需 --download）
info "Test: crbs build --remote --attach <build_id> --download"
ATTACH_OUTPUT=$($CRBS build --remote "$BASE" --token "$CRBS_SERVER_TOKEN" --attach "$DETACH_BUILD_ID" --download 2>/dev/null)
assert_contains "SUCCEEDED" "$ATTACH_OUTPUT" "Attach with build_id reports success"
assert_contains "hello-" "$ATTACH_OUTPUT" "Attach output references hello artifact"
# 验证产物下载到本地 results/（布局 results/{product}/{pkg}/{build_id}，CWD 相对）
LOCAL_RESULT_DIR=$(find "$SRPM_DIR/results/$PRODUCT" -maxdepth 4 -type d -name "${DETACH_BUILD_ID}" 2>/dev/null | head -1)
if [[ -d "$LOCAL_RESULT_DIR" ]]; then
    assert_contains "RPMS" "$(ls "$LOCAL_RESULT_DIR")" "Artifacts downloaded to local results dir"
else
    echo -e "${RED}[FAIL]${NC} Local result dir not found for build_id $DETACH_BUILD_ID"
    FAIL=$((FAIL+1))
fi

# 3. attach --follow-logs 能拉取日志
info "Test: crbs build --remote --attach <id> --follow-logs"
FOLLOW_OUTPUT=$($CRBS build --remote "$BASE" --token "$CRBS_SERVER_TOKEN" --attach "$DETACH_BUILD_ID" --follow-logs 2>/dev/null)
assert_contains "CRBS_PHASE" "$FOLLOW_OUTPUT" "Attach --follow-logs streams build log"
assert_contains "SUCCEEDED" "$FOLLOW_OUTPUT" "Attach --follow-logs reports success"

# 7. remote status 列表与单任务查询
info "Test: crbs status --remote"
STATUS_OUTPUT=$($CRBS status --remote "$BASE" --token "$CRBS_SERVER_TOKEN" 2>/dev/null)
assert_contains "$DETACH_TASK_ID" "$STATUS_OUTPUT" "Remote status list contains task id"
assert_contains "succeeded" "$STATUS_OUTPUT" "Remote status list shows succeeded phase"
assert_contains "hello" "$STATUS_OUTPUT" "Remote status list shows package name"

info "Test: crbs status --remote <task_id>"
# 远程单查按 task id 解析（status/remote.rs：full numeric task id）。
STATUS_SINGLE=$($CRBS status "$DETACH_TASK_ID" --remote "$BASE" --token "$CRBS_SERVER_TOKEN" 2>/dev/null)
assert_contains "succeeded" "$STATUS_SINGLE" "Remote status single shows succeeded"

info "Test: crbs status --remote <id> --profile"
# profile 模式的 ID 按 build id 解析（status/remote.rs：子构建级属性）。
# 现行 server 恒返回嵌套 profile（profile.json 缺失直接 404），human 渲染
# 走 format_profile 分支：摘要头行 + "Phase breakdown:" + 引擎 phase 行；
# "rpms:" 列表只存在于旧 server（wire 无嵌套字段）的降级分支，现行部署
# 断言不到。标记取 "Phase breakdown:"（format_profile 无条件输出）+
# "install-srpm"（全量构建必经引擎阶段，输出中无同名词碰撞）。
STATUS_PROFILE=$($CRBS status "$DETACH_BUILD_ID" --remote "$BASE" --token "$CRBS_SERVER_TOKEN" --profile 2>/dev/null)
assert_contains "Profile for build" "$STATUS_PROFILE" "Remote status profile header"
assert_contains "Phase breakdown:" "$STATUS_PROFILE" "Remote status profile renders phase breakdown"
assert_contains "install-srpm" "$STATUS_PROFILE" "Remote status profile lists engine phases"

info "Test: crbs status --remote --format json"
STATUS_JSON=$($CRBS status --remote "$BASE" --token "$CRBS_SERVER_TOKEN" --format json 2>/dev/null)
assert_contains '"phase":' "$STATUS_JSON" "Remote status JSON contains phase"
assert_contains '"id":' "$STATUS_JSON" "Remote status JSON contains id"

# 8. remote cancel
info "Test: crbs cancel --remote"
CANCEL_DETACH_OUTPUT=$($CRBS build "$SRPM" --product "$PRODUCT" --remote "$BASE" --token "$CRBS_SERVER_TOKEN" --detach 2>/dev/null)
CANCEL_BUILD_ID=$(echo "$CANCEL_DETACH_OUTPUT" | grep "build_id:" | awk '{print $3}')
CANCEL_TASK_ID=$(echo "$CANCEL_DETACH_OUTPUT" | grep "^  task_id:" | awk '{print $2}')
info "  cancel task_id=$CANCEL_TASK_ID (build_id=$CANCEL_BUILD_ID)"
# cancel --remote 按 **task id** 解析（cmd/mod.rs → POST /api/v1/tasks/{id}/cancel）；
# 传 build id 会解析到错误任务。轮询与产物检查仍在 build id 域
# （/api/v1/builds/{id} 是子构建记录）。
$CRBS cancel "$CANCEL_TASK_ID" --remote "$BASE" --token "$CRBS_SERVER_TOKEN" 2>/dev/null
poll_remote_build "$CANCEL_BUILD_ID" >/dev/null
R=$(curl -s "${AUTH[@]}" "${BASE}/api/v1/builds/${CANCEL_BUILD_ID}")
CANCEL_PHASE=$(echo "$R" | python3 -c "import json,sys; print(json.load(sys.stdin)['phase'])" 2>/dev/null || true)
assert_status "cancelled" "$CANCEL_PHASE" "Remote cancel marks build as cancelled"

# 4. wait 模式默认不打印日志，只显示状态行
info "Test: crbs build --remote (wait, no logs)"
WAIT_OUTPUT=$($CRBS build "$SRPM" --product "$PRODUCT" --remote "$BASE" --token "$CRBS_SERVER_TOKEN" 2>/dev/null)
assert_contains "SUCCEEDED" "$WAIT_OUTPUT" "Remote wait mode succeeds"
assert_not_contains "CRBS_PHASE" "$WAIT_OUTPUT" "Remote wait mode without --follow-logs does not stream log"
assert_contains "phase=" "$WAIT_OUTPUT" "Remote wait mode shows status line"

# 5. wait 模式 + --follow-logs 打印日志
info "Test: crbs build --remote --follow-logs"
FOLLOW_WAIT_OUTPUT=$($CRBS build "$SRPM" --product "$PRODUCT" --remote "$BASE" --token "$CRBS_SERVER_TOKEN" --follow-logs 2>/dev/null)
assert_contains "SUCCEEDED" "$FOLLOW_WAIT_OUTPUT" "Remote --follow-logs succeeds"
assert_contains "CRBS_PHASE" "$FOLLOW_WAIT_OUTPUT" "Remote --follow-logs streams build log"

# 6. server 数字 ID 路由（curl 直接访问）
# 短 ID（UUID/前缀）路由已随 i64 ID 改革移除：服务端 {id} 按数字精确解析。
info "Test: server numeric ID routing"
R=$(curl -s "${AUTH[@]}" "${BASE}/api/v1/builds/${DETACH_BUILD_ID}")
assert_contains '"succeeded"' "$R" "GET /builds/{id} resolves build"

R=$(curl -s -o /dev/null -w "%{http_code}" -N "${AUTH[@]}" "${BASE}/api/v1/builds/${DETACH_BUILD_ID}/logs?offset=0")
assert_status "200" "$R" "GET /builds/{id}/logs resolves"

R=$(curl -s -o /dev/null -w "%{http_code}" "${AUTH[@]}" "${BASE}/api/v1/builds/${DETACH_BUILD_ID}/artifacts")
assert_status "200" "$R" "GET /builds/{id}/artifacts resolves"

R=$(curl -s -o /dev/null -w "%{http_code}" "${AUTH[@]}" "${BASE}/api/v1/builds/${DETACH_BUILD_ID}/profile")
assert_status "200" "$R" "GET /builds/{id}/profile resolves"

echo ""
if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}All ${PASS} tests PASSED${NC}"
    exit 0
else
    echo -e "${RED}${FAIL} test(s) FAILED, ${PASS} passed${NC}"
    exit 1
fi
