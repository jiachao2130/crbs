#!/bin/bash
# Parity 测试：验证 chroot 与 nspawn backend 构建结果一致
# 需要 root + 已初始化的产品 + SRPM
#
# 运行:
#   sudo ./tests/parity.sh <product> <srpm> [stage]
#
# 参数:
#   product  已初始化的产品名（如 fedora）
#   srpm     待构建的 SRPM 文件路径
#   stage    构建阶段，可选 bb / bs / ba（默认 ba）
#
# 比对维度：
#   - RPM/SRPM 文件名列表一致
#   - 每个 RPM 的 metadata（rpm -qlp --dump：path size mtime digest mode owner group）一致
#   - 每个 RPM 的 cpio payload sha256（二进制内容）一致
#   - build.log 产物存在
#   - SQLite backend 记录正确
#
# 注意：
#   - 假设两个 backend 使用相同的 SOURCE_DATE_EPOCH；如 --dump 比较失败且
#     仅 mtime 差异，说明 SOURCE_DATE_EPOCH 链路不一致，不是 backend bug。
#   - bs/ba 阶段会额外比对 SRPMS 目录下的源码包。

set -euo pipefail

CRBS=${CRBS:-/usr/local/bin/crbs}
DB=${DB:-/var/lib/crbs/crbs.db}

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
die() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
error() { echo -e "${RED}[FAIL]${NC} $*"; }

usage() {
    echo "Usage: sudo $0 <product> <srpm> [bb|bs|ba]"
    echo "  stage defaults to ba (binary + source)"
    echo "Example: sudo $0 fedora /path/to/hello.src.rpm ba"
    exit 1
}

if [[ "$EUID" -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

if [[ $# -lt 2 || $# -gt 3 ]]; then
    usage
fi

STAGE="${3:-ba}"
case "$STAGE" in
    bb|bs|ba) ;;
    *) error "invalid stage: $STAGE (expected bb, bs, or ba)"; usage ;;
esac

# ─── 校验依赖工具 ──────────────────────────────────────────────

for tool in rpm sqlite3 diff rpm2cpio find; do
    command -v "$tool" >/dev/null || { error "missing tool: $tool"; exit 1; }
done

PRODUCT="$1"
SRPM="$2"
PKG_NAME=$(basename "$SRPM" .src.rpm)

info "Product: $PRODUCT"
info "SRPM: $SRPM"
info "Package: $PKG_NAME"
info "Stage: $STAGE"

# ─── 清理旧结果 ────────────────────────────────────────────────

RESULT_BASE="/var/lib/crbs/results/$PRODUCT/$PKG_NAME"
# 删除守卫：目标必须是 results/<product>/<pkg> 三段形态——变量为空/带 `..`
# 时会波及无关历史结果。
case "$RESULT_BASE" in
    /var/lib/crbs/results/?*/?*)
        [[ "$RESULT_BASE" != *".."* ]] || die "refusing suspicious RESULT_BASE: $RESULT_BASE"
        if [[ -d "$RESULT_BASE" ]]; then
            warn "Removing old results: $RESULT_BASE"
            rm -rf "$RESULT_BASE"
        fi
        ;;
    *)
        die "refusing unexpected RESULT_BASE shape: $RESULT_BASE"
        ;;
esac

# 同时清理 SQLite 中该包的历史记录，避免查询命中已删除的 result_dir
sqlite3 "$DB" "DELETE FROM builds WHERE pkg_name='$PKG_NAME';" 2>/dev/null || true

# ─── 比较辅助函数 ──────────────────────────────────────────────

# 比较两个 result_dir 下指定子目录（RPMS 或 SRPMS）的 RPM 产出。
# 用法: compare_rpms <label> <chroot_dir> <nspawn_dir> <check_content>
#   label          显示用标签（如 "RPMS"、"SRPMS"）
#   chroot_dir     chroot result 下的子目录路径
#   nspawn_dir     nspawn result 下的子目录路径
#   check_content  1 = 同时比对 metadata + payload；0 = 仅比对文件名列表
#
# 二进制 RPM 的 ELF 内容受 debug info / build-id 影响不可复现，故 RPMS 只比
# 文件名列表；SRPMS 是纯文本（spec + 源码 + 补丁），可比对全部维度。
compare_rpms() {
    local label="$1" chroot_dir="$2" nspawn_dir="$3" check_content="$4"

    if [[ ! -d "$chroot_dir" && ! -d "$nspawn_dir" ]]; then
        info "$label: absent in both (expected for this stage)"
        return 0
    fi

    local chroot_list nspawn_list
    chroot_list=$(find "$chroot_dir" -name '*.rpm' 2>/dev/null | sort)
    nspawn_list=$(find "$nspawn_dir" -name '*.rpm' 2>/dev/null | sort)

    # 比较文件名
    if ! diff <(echo "$chroot_list" | xargs -n1 basename 2>/dev/null) \
              <(echo "$nspawn_list" | xargs -n1 basename 2>/dev/null); then
        error "$label filename lists differ"
        return 1
    fi
    info "$label filenames: SAME"

    # 仅当 check_content=1 时比对 metadata + payload（用于 SRPMS）
    if [[ "$check_content" != "1" ]]; then
        return 0
    fi

    # 比较每个 RPM 的 metadata + payload
    local differs=0
    while IFS= read -r chroot_rpm; do
        [[ -z "$chroot_rpm" ]] && continue
        local name nspawn_rpm
        name=$(basename "$chroot_rpm")
        nspawn_rpm=$(find "$nspawn_dir" -name "$name" | head -1)

        # --dump 输出: path size mtime digest mode owner group ...
        if ! diff <(rpm -qlp --dump "$chroot_rpm" | sort) \
                  <(rpm -qlp --dump "$nspawn_rpm" | sort) > /dev/null; then
            error "$label metadata differs: $name"
            differs=1
        fi

        # cpio payload sha256（二进制内容）
        if ! diff <(rpm2cpio "$chroot_rpm" | sha256sum) \
                  <(rpm2cpio "$nspawn_rpm" | sha256sum) > /dev/null; then
            error "$label payload differs: $name"
            differs=1
        fi
    done <<< "$chroot_list"

    if [[ $differs -eq 1 ]]; then
        return 1
    fi
    info "$label metadata (--dump): SAME"
    info "$label payload (cpio sha256): SAME"
    return 0
}

# ─── chroot 构建 ───────────────────────────────────────────────

info "Building with chroot backend (stage=$STAGE)..."
$CRBS build "$SRPM" --product "$PRODUCT" --backend chroot --stage "$STAGE"

CHROOT_RESULT=$(sqlite3 "$DB" \
    "SELECT result_dir FROM builds WHERE pkg_name='$PKG_NAME' AND backend='chroot' ORDER BY started_at DESC LIMIT 1;")
if [[ -z "$CHROOT_RESULT" || ! -d "$CHROOT_RESULT" ]]; then
    error "chroot build produced no result directory"
    exit 1
fi
info "chroot result: $CHROOT_RESULT"

# ─── nspawn 构建 ───────────────────────────────────────────────

info "Building with nspawn backend (stage=$STAGE)..."
$CRBS build "$SRPM" --product "$PRODUCT" --backend nspawn --stage "$STAGE"

NSPAWN_RESULT=$(sqlite3 "$DB" \
    "SELECT result_dir FROM builds WHERE pkg_name='$PKG_NAME' AND backend='nspawn' ORDER BY started_at DESC LIMIT 1;")
if [[ -z "$NSPAWN_RESULT" || ! -d "$NSPAWN_RESULT" ]]; then
    error "nspawn build produced no result directory"
    exit 1
fi
info "nspawn result: $NSPAWN_RESULT"

# ─── 比较 RPM 产出 ─────────────────────────────────────────────

FAILED=0

# bb/ba: 比较二进制 RPM（仅文件名列表，ELF 内容不可复现）
if [[ "$STAGE" == "bb" || "$STAGE" == "ba" ]]; then
    compare_rpms "RPMS" "$CHROOT_RESULT/RPMS" "$NSPAWN_RESULT/RPMS" 0 || FAILED=1
fi

# bs/ba: 比较源码 RPM（全维度：文件名 + metadata + payload）
if [[ "$STAGE" == "bs" || "$STAGE" == "ba" ]]; then
    compare_rpms "SRPMS" "$CHROOT_RESULT/SRPMS" "$NSPAWN_RESULT/SRPMS" 1 || FAILED=1
fi

if [[ $FAILED -eq 1 ]]; then
    error "Parity test FAILED"
    exit 1
fi

# ─── 比较构建日志存在性 ────────────────────────────────────────

for f in build.log; do
    if [[ ! -f "$CHROOT_RESULT/$f" ]]; then
        error "Missing $f in chroot result"
        exit 1
    fi
    if [[ ! -f "$NSPAWN_RESULT/$f" ]]; then
        error "Missing $f in nspawn result"
        exit 1
    fi
done
info "Build logs: present in both"

# ─── 比较 SQLite backend 记录 ─────────────────────────────────

CHROOT_BACKEND=$(sqlite3 "$DB" \
    "SELECT backend FROM builds WHERE result_dir='$CHROOT_RESULT';" 2>/dev/null || echo "unknown")
NSPAWN_BACKEND=$(sqlite3 "$DB" \
    "SELECT backend FROM builds WHERE result_dir='$NSPAWN_RESULT';" 2>/dev/null || echo "unknown")

if [[ "$CHROOT_BACKEND" != "chroot" ]]; then
    error "chroot build backend record is '$CHROOT_BACKEND', expected 'chroot'"
    exit 1
fi
if [[ "$NSPAWN_BACKEND" != "nspawn" ]]; then
    error "nspawn build backend record is '$NSPAWN_BACKEND', expected 'nspawn'"
    exit 1
fi
info "SQLite backend records: correct"

# ─── 总结 ──────────────────────────────────────────────────────

echo ""
info "Parity test PASSED (stage=$STAGE)"
info "  chroot: $CHROOT_RESULT"
info "  nspawn: $NSPAWN_RESULT"
