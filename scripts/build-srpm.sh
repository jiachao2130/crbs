#!/bin/bash
# build-srpm.sh: 生成 CRBS 源码 RPM (SRPM)
#
# 用法：
#   bash scripts/build-srpm.sh                # 生成 SRPM
#   bash scripts/build-srpm.sh --remote U@H   # 生成后送至目标机 rpmbuild --rebuild
#   bash scripts/build-srpm.sh -v             # 保留临时目录并输出细节
#
# SRPM 只含源码与 spec 声明的补丁，不含 vendored 依赖。目标机 rebuild 时由
# cargo 按 Cargo.lock 拉取依赖并编译（需访问 crates.io 或已配置的 cargo 镜像）。
# 产物为架构无关的 rpmbuild/SRPMS/crbs-<ver>-<rel>.src.rpm。

set -euo pipefail
# 依赖：rpmbuild、tar

VERBOSE=0
REMOTE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -v|--verbose)  VERBOSE=1; shift ;;
        --remote)      [[ $# -ge 2 ]] || { echo "错误: --remote 需要参数 USER@HOST" >&2; exit 2; }
                       REMOTE="$2"; shift 2 ;;
        -h|--help)     sed -n '1,/^$/p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) echo "未知参数: $1（-h 看用法）" >&2; exit 2 ;;
    esac
done

note() { echo "[build-srpm] $*" >&2; }

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

SPEC_FILE="$PROJECT_ROOT/crbs.spec"
[[ -f "$SPEC_FILE" ]] || { echo "错误: 找不到 spec: $SPEC_FILE" >&2; exit 1; }
NAME="crbs"
VERSION="$(awk '/^Version:/ {print $2; exit}' "$SPEC_FILE")"
[[ -n "$VERSION" ]] || { echo "错误: spec 无 Version" >&2; exit 1; }

# 补丁清单从 spec 的 PatchN 行解析，spec 是唯一事实源
PATCH_FILES=()
while read -r patchfile; do
    [[ -f "patches/$patchfile" ]] || { echo "错误: 缺少补丁 patches/$patchfile" >&2; exit 1; }
    PATCH_FILES+=("$patchfile")
done < <(sed -n 's/^Patch[0-9]*:[[:space:]]*//p' "$SPEC_FILE")

SRC_DIR_NAME="${NAME}-${VERSION}-src"
# 打包树放仓库 target/ 下；成功且非 verbose 时清理，失败保留并打印路径
mkdir -p "$PROJECT_ROOT/target"
TOPDIR="$(mktemp -d "$PROJECT_ROOT/target/crbs-srpm.XXXXXX")"
cleanup() {
    rc=$?
    if [[ $rc -ne 0 ]]; then
        note "失败，保留临时目录供排查: $TOPDIR"
        return $rc
    fi
    [[ $VERBOSE -eq 0 ]] && rm -rf "$TOPDIR"
    return $rc
}
trap cleanup EXIT
[[ $VERBOSE -eq 1 ]] && note "临时目录: $TOPDIR"

# ---------- 1. 源码树 ----------
note "1/3 组装源码树"
SRC_DIR="$TOPDIR/$SRC_DIR_NAME"
mkdir -p "$SRC_DIR"
cp Cargo.toml Cargo.lock LICENSE README.md "$SRC_DIR/"
if [[ -f CHANGELOG.md ]]; then cp CHANGELOG.md "$SRC_DIR/"; fi
cp -r crates examples packaging "$SRC_DIR/"
# 只收源码构建与单测需要的 deploy 脚本，不带入开发部署工具
mkdir -p "$SRC_DIR/deploy"
cp deploy/backup-crbs.sh deploy/upgrade-resource-schema-sqlite.sh \
   deploy/upgrade-resource-schema-pg.sh deploy/upgrade-resource-schema-worker.sh "$SRC_DIR/deploy/"

TARBALL="$TOPDIR/${NAME}-${VERSION}.tar.gz"
tar czf "$TARBALL" -C "$TOPDIR" "$SRC_DIR_NAME"

# ---------- 2. rpmbuild -bs ----------
note "2/3 rpmbuild -bs"
RBT="$TOPDIR/rpmbuild"
mkdir -p "$RBT/SOURCES" "$RBT/SPECS"
cp "$TARBALL" "$RBT/SOURCES/"
for patchfile in ${PATCH_FILES[@]+"${PATCH_FILES[@]}"}; do
    cp "patches/$patchfile" "$RBT/SOURCES/"
done
cp "$SPEC_FILE" "$RBT/SPECS/"
# 置空 dist：SRPM 不绑定打包机发行版，rebuild 时由目标机自带 dist 决定
BSLOG="$TOPDIR/rpmbuild-bs.log"
rpmbuild -bs --define "_topdir $RBT" --define 'dist %{nil}' "$RBT/SPECS/$NAME.spec" > "$BSLOG"
SRPM_OUT="$(sed -n 's/^Wrote: //p' "$BSLOG" | head -1)"
[[ -n "$SRPM_OUT" && -f "$SRPM_OUT" ]] || { echo "错误: 未生成 SRPM（见 $BSLOG）" >&2; exit 1; }

# ---------- 3. 输出 ----------
note "3/3 输出"
OUTDIR="$PROJECT_ROOT/rpmbuild/SRPMS"
mkdir -p "$OUTDIR"
cp "$SRPM_OUT" "$OUTDIR/"
echo "$OUTDIR/$(basename "$SRPM_OUT")"

if [[ -n "$REMOTE" ]]; then
    note "远端真机 rebuild：$REMOTE（目标机需可访问 crates.io 或 cargo 镜像）"
    SRPM_NAME="$(basename "$SRPM_OUT")"
    scp -q "$OUTDIR/$SRPM_NAME" "$REMOTE:/tmp/"
    # _topdir 必须由远端 shell 展开 $HOME（rpm 宏不认 ~）
    if ! ssh -o BatchMode=yes "$REMOTE" \
        "rpmbuild --rebuild --define \"_topdir \$HOME/rpmbuild\" /tmp/$SRPM_NAME" 2>&1 | tail -10; then
        ssh -o BatchMode=yes "$REMOTE" "rm -f /tmp/$SRPM_NAME" || true
        echo "错误: 远端 rebuild 失败" >&2
        exit 1
    fi
    ssh -o BatchMode=yes "$REMOTE" 'ls ~/rpmbuild/RPMS/*/crbs-*.rpm 2>/dev/null | tail -6' || true
    ssh -o BatchMode=yes "$REMOTE" "rm -f /tmp/$SRPM_NAME"
fi
