#!/bin/bash
# backup-crbs.sh — CRBS 备份：SQLite 在线快照 + 可选 artifacts 归档 + 滚动保留。
#
# 用法：
#   bash deploy/backup-crbs.sh [--crbs-root DIR] [--backup-dir DIR] [--keep N] [--artifacts]
#
# 行为说明：
#   - DB 快照用 `sqlite3 <db> ".backup '<dest>'"` 在线生成一致性副本（不要用 cp 拷活库，
#     会得到撕裂的 WAL 状态）。crbs.db 不存在时打 WARN 跳过：PostgreSQL 部署的库不在
#     本脚本职责范围内，请自行 pg_dump。
#   - 备份文件名带秒级时间戳（crbs-db-YYYYmmdd-HHMMSS.db /
#     crbs-artifacts-YYYYmmdd-HHMMSS.tar.gz），每次运行独立命名；同一秒并发时自动顺延，
#     互不覆盖（并发路径隔离纪律）。
#   - 滚动保留只删除严格匹配本脚本命名模式（固定前缀 + 8位日期-6位时间 + 固定后缀）的
#     旧文件，备份目录里其他文件（哪怕名字相似）一律不动——绝不按共享名删除无关文件。
#
# 定时执行模板见 packaging/crbs-backup.service + packaging/crbs-backup.timer。

set -euo pipefail

CRBS_ROOT="/var/lib/crbs"
BACKUP_DIR=""
KEEP=7
WITH_ARTIFACTS=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

usage() {
    cat <<'EOF'
用法: backup-crbs.sh [--crbs-root DIR] [--backup-dir DIR] [--keep N] [--artifacts]

  --crbs-root DIR   CRBS 状态根目录，默认 /var/lib/crbs（其下应有 crbs.db、artifacts/）
  --backup-dir DIR  备份输出目录，默认 <crbs-root>/backups。
                    注意默认位置与原数据同盘；生产环境建议指向独立存储，
                    否则磁盘故障会同时丢掉原数据和备份。
  --keep N          每类备份各自保留的份数，默认 7（正整数）
  --artifacts       额外归档 <crbs-root>/artifacts 为 tar.gz（体积可能很大，默认关闭）
  --help            显示本帮助
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --crbs-root)  CRBS_ROOT="${2:?--crbs-root 需要一个目录参数}"; shift 2 ;;
        --backup-dir) BACKUP_DIR="${2:?--backup-dir 需要一个目录参数}"; shift 2 ;;
        --keep)       KEEP="${2:?--keep 需要一个数字参数}"; shift 2 ;;
        --artifacts)  WITH_ARTIFACTS=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        *)            log_error "未知参数: $1"; usage >&2; exit 1 ;;
    esac
done

BACKUP_DIR="${BACKUP_DIR:-$CRBS_ROOT/backups}"

if ! [[ "$KEEP" =~ ^[0-9]+$ ]] || [ "$KEEP" -lt 1 ]; then
    log_error "--keep 需要正整数，当前值: $KEEP"
    exit 1
fi

# 本脚本命名模式（滚动清理的白名单，正则锚定全名）：
# crbs-db-YYYYmmdd-HHMMSS.db / crbs-artifacts-YYYYmmdd-HHMMSS.tar.gz
DB_NAME_RE='^crbs-db-[0-9]{8}-[0-9]{6}\.db$'
ART_NAME_RE='^crbs-artifacts-[0-9]{8}-[0-9]{6}\.tar\.gz$'

# 滚动保留：删除超出 KEEP 份数的最老备份。只碰严格匹配本脚本命名模式的文件。
rotate_backups() {
    local regex="$1" old name
    # sort -r（新→旧）后跳过最新 KEEP 行，余下即待删的旧备份。
    # shellcheck disable=SC2012  # 仅为取文件名列表；可删项已由 regex 全名锚定白名单化
    old=$(ls -1 "$BACKUP_DIR" 2>/dev/null | grep -E "$regex" | sort -r | tail -n +"$((KEEP + 1))" || true)
    while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        rm -f -- "$BACKUP_DIR/$name"
        log_info "滚动清理: 删除旧备份 ${name}（每类保留 ${KEEP} 份）"
    done <<< "$old"
}

# 产出文件 0660（对齐 crbs 文件权限不变量：文件 0660 / 目录 2770，crbs 组可读写）
umask 0007

if [[ ! -d "$BACKUP_DIR" ]]; then
    mkdir -p "$BACKUP_DIR"
    # chmod 失败要 WARN（通常意味着权限未生效）；chgrp 失败仅忽略（非 root / 无 crbs
    # 组的环境必然 EPERM，属预期路径，组可写已足够本进程访问）。
    chmod 2770 "$BACKUP_DIR" || log_warn "chmod 2770 $BACKUP_DIR 失败，目录权限可能不符合预期"
    chgrp crbs "$BACKUP_DIR" 2>/dev/null || true
    log_info "创建备份目录: $BACKUP_DIR (2770)"
fi

# 秒级时间戳；同一秒并发运行时顺延，保证每次运行写独立文件
STAMP=$(date +%Y%m%d-%H%M%S)
TRIES=0
while [[ -e "$BACKUP_DIR/crbs-db-${STAMP}.db" || -e "$BACKUP_DIR/crbs-artifacts-${STAMP}.tar.gz" ]]; do
    TRIES=$((TRIES + 1))
    if [ "$TRIES" -ge 5 ]; then
        log_error "备份文件名持续冲突（重试 5 次），请检查 $BACKUP_DIR"
        exit 1
    fi
    sleep 1
    STAMP=$(date +%Y%m%d-%H%M%S)
done

DID_DB=0
DID_ART=0

# ---- 1) SQLite 在线快照 ----
DB_PATH="$CRBS_ROOT/crbs.db"
if [[ ! -f "$DB_PATH" ]]; then
    log_warn "未找到 ${DB_PATH}，跳过 DB 快照（PostgreSQL 部署请自行 pg_dump，不在本脚本范围）"
else
    command -v sqlite3 >/dev/null 2>&1 || { log_error "需要 sqlite3 命令，但未安装"; exit 1; }
    DB_DEST="$BACKUP_DIR/crbs-db-${STAMP}.db"
    # .backup 对运行中的库也安全（自带锁与页级拷贝），远优于 cp 活库
    sqlite3 "$DB_PATH" ".backup '$DB_DEST'"
    log_info "DB 快照完成: $DB_DEST ($(du -h "$DB_DEST" | cut -f1))"
    DID_DB=1
    rotate_backups "$DB_NAME_RE"
fi

# ---- 2) artifacts 归档（可选）----
if [ "$WITH_ARTIFACTS" -eq 1 ]; then
    ART_SRC="$CRBS_ROOT/artifacts"
    if [[ ! -d "$ART_SRC" ]]; then
        log_warn "未找到 ${ART_SRC}，跳过 artifacts 归档"
    else
        command -v tar >/dev/null 2>&1 || { log_error "需要 tar 命令，但未安装"; exit 1; }
        ART_DEST="$BACKUP_DIR/crbs-artifacts-${STAMP}.tar.gz"
        # -C 让归档内为相对路径（顶层 artifacts/…）；只归档 artifacts 子树，
        # 备份目录不在其中，不存在自包含问题
        tar -C "$CRBS_ROOT" -czf "$ART_DEST" artifacts
        log_info "artifacts 归档完成: $ART_DEST ($(du -h "$ART_DEST" | cut -f1))"
        DID_ART=1
        rotate_backups "$ART_NAME_RE"
    fi
fi

if [ "$DID_DB" -eq 0 ] && [ "$DID_ART" -eq 0 ]; then
    log_warn "本次未产出任何备份（crbs.db 与 artifacts 均缺失？请检查 --crbs-root 路径）"
else
    log_info "备份结束: 目录=$BACKUP_DIR 保留=${KEEP}/类 db快照=$DID_DB artifacts归档=$DID_ART"
fi
