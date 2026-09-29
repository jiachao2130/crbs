#!/bin/bash
# upgrade-resource-schema-sqlite.sh — hub SQLite 库 schema 桥接升级（幂等）。
#
# 用途：schema 版本闩恒 (1,1)、无增量迁移——旧库升级新二进制后 ensure_schema
# 戳判等通过但缺新对象，首次相关 UPDATE 才爆列错。本脚本按 baseline
#（crates/crbs-core/src/state/schema.sql）现文本补齐升级对象，纯加法、
# 零破坏、可重复执行：
#   1. builds +10 列：req_min_mem_kb / req_min_ncpu / req_min_disk_kb /
#      peak_total_kb / disk_wbytes / oom_killed / sample_backend / sample_ncpu /
#      peak_tmpfs_kb / product_config_toml
#   2. workers +2 列：disk_free_kb / resource_caps
#   3. worker_telemetry_samples +1 列：disk_free_kb
#   4. 新表 package_resource_profiles（PK product/source_name/arch）+
#      索引 idx_profiles_product_mem；表已存在的存量库补 +2 列
#      learned_ema_tmpfs_kb / learned_max_tmpfs_kb（tmpfs 峰值画像 EMA/最大）
#   5. 新表 task_labels（PK task_id/key，FK CASCADE）+ 索引 idx_task_labels_key_value
#   6. builds 索引 idx_builds_srpm_sha256（partial，血缘锚内容检索）
# 新二进制启动时另有对象探测 fail-closed 双保险（缺对象拒启并指引到本脚本）。
#
# 画像表以源码包基础名（source_name）为键：检测到以 pkg_name 为键的旧表时
# 本脚本拒绝执行（不自动迁移/改键）。请备份后手动
# DROP TABLE package_resource_profiles 再重跑；重建空表后本脚本清除回填标记，
# 重启 crbs-server 从 builds 历史重建学习面（声明下限需重新录入）。
#
# 用法（hub 本机、root；PostgreSQL 部署请改用 upgrade-resource-schema-pg.sh）：
#   sudo bash deploy/upgrade-resource-schema-sqlite.sh [--db PATH]
#     --db PATH  SQLite 库文件路径。缺省按 /etc/crbs/server.toml 解析：
#                state_db_path 优先，否则 {crbs_root}/crbs.db（crbs_root 缺省
#                /var/lib/crbs）；均未配置即 /var/lib/crbs/crbs.db
#
# 前置与建议：
#   - 目标库已由任意版本 crbs-server 初始化过（builds 表在位）；全新安装直接
#     启动 crbs-server 落全量 baseline，无需本脚本
#   - 建议先备份（deploy/backup-crbs.sh）；脚本只加列建表，不改不删任何数据
#   - 服务运行中会与本脚本争 sqlite 写锁（已设 busy_timeout 等待），建议先停
#     crbs-server / crbs-worker 再执行

set -euo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; NC='\033[0m'
log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die() { log_error "$*"; exit 1; }

usage() {
    cat <<'EOF'
用法: upgrade-resource-schema-sqlite.sh [--db PATH]

  --db PATH  SQLite 库文件路径。缺省按 /etc/crbs/server.toml 解析
             （state_db_path 优先，否则 {crbs_root}/crbs.db），
             均未配置即 /var/lib/crbs/crbs.db
EOF
}

SERVER_TOML=/etc/crbs/server.toml
DB=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --db) DB="${2:?--db 需要一个路径参数}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) log_error "未知参数: $1"; usage >&2; exit 2 ;;
    esac
done

# 默认路径与 ServerConfig::state_db_path()/server_crbs_root() 缺省链一致：
# state_db_path > {crbs_root}/crbs.db > /var/lib/crbs/crbs.db。
# sed 抽引号值同 reinit-hub.sh 惯例。
if [[ -z $DB ]]; then
    DB=$(grep -E '^\s*state_db_path' "$SERVER_TOML" 2>/dev/null | head -1 | sed 's/.*"\(.*\)".*/\1/' || true)
fi
if [[ -z $DB ]]; then
    CRBS_ROOT=$(grep -E '^\s*crbs_root' "$SERVER_TOML" 2>/dev/null | head -1 | sed 's/.*"\(.*\)".*/\1/' || true)
    DB="${CRBS_ROOT:-/var/lib/crbs}/crbs.db"
fi

command -v sqlite3 >/dev/null || die "需要 sqlite3 命令，但未安装"
[[ -f $DB ]] || die "库文件不存在: $DB（首次部署请先启动 crbs-server 初始化 baseline）"

# busy_timeout 只对本连接生效，故每条命令各自前缀：与在跑服务并发时等待而非
# 立即报 database is locked。CLI 会把 PRAGMA 自身的返回值（5000）打成结果首行，
# tail -n +2 剥掉它只留业务查询结果；pipefail 让 sqlite3 的失败穿透 tail。
sq() { sqlite3 "$DB" "PRAGMA busy_timeout=5000; $1" | tail -n +2; }

has_table() { [[ $(sq "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='$1'") == 1 ]]; }
has_col()   { [[ $(sq "SELECT COUNT(*) FROM pragma_table_info('$1') WHERE name='$2'") == 1 ]]; }
has_index() { [[ $(sq "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='$1'") == 1 ]]; }

for t in builds workers worker_telemetry_samples; do
    has_table "$t" || die "表 $t 不存在：$DB 不是已初始化的 crbs 库（或 --db 路径配错）"
done

# 旧画像表（pkg_name 主键）与新代码不兼容：拒绝而非"已存在跳过"，避免留下
# 列探测会拒启的半旧结构。
if has_table package_resource_profiles && ! has_col package_resource_profiles source_name; then
    die "检测到旧 pkg_name 画像表（与新 source_name 主键不兼容）。请备份后手动执行 sqlite3 \"$DB\" 'DROP TABLE package_resource_profiles;' 再重跑本脚本；重启 crbs-server 会从 builds 历史重建学习面"
fi

log_info "升级计划（幂等：已存在的对象一律跳过，不动数据）："
log_info "  库文件: $DB"
log_info "  ALTER TABLE builds ADD COLUMN ×10（req_min_* / peak_total_kb / disk_wbytes / oom_killed / sample_backend / sample_ncpu / peak_tmpfs_kb / product_config_toml）"
log_info "  ALTER TABLE workers ADD COLUMN ×2（disk_free_kb / resource_caps）"
log_info "  ALTER TABLE worker_telemetry_samples ADD COLUMN ×1（disk_free_kb）"
log_info "  CREATE TABLE IF NOT EXISTS package_resource_profiles + CREATE INDEX idx_profiles_product_mem"
log_info "  ALTER TABLE package_resource_profiles ADD COLUMN ×2（learned_ema_tmpfs_kb / learned_max_tmpfs_kb，已存在跳过）"
log_info "  CREATE TABLE IF NOT EXISTS task_labels + CREATE INDEX idx_task_labels_key_value"
log_info "  CREATE INDEX IF NOT EXISTS idx_builds_srpm_sha256（partial）"
log_warn "建议先备份（deploy/backup-crbs.sh）；服务运行中建议先停 crbs-server / crbs-worker"

# ---- 补列 ----
# 列定义文本 = baseline 对应列逐字（含 CHECK）；全部可空、无 DEFAULT：ADD COLUMN
# 给存量行统一填 NULL，与"缺数据 = 降级放行"的列语义一致。
ensure_col() {
    if has_col "$1" "$2"; then
        log_info "  跳过（已存在）: $1.$2"
    else
        sq "ALTER TABLE $1 ADD COLUMN $2 $3" || die "加列失败: $1.$2"
        log_info "  已加列: $1.$2"
    fi
}

log_info "补列…"
ensure_col builds req_min_mem_kb "INTEGER"
ensure_col builds req_min_ncpu "INTEGER"
ensure_col builds req_min_disk_kb "INTEGER"
ensure_col builds peak_total_kb "INTEGER"
ensure_col builds disk_wbytes "INTEGER"
ensure_col builds oom_killed "INTEGER CHECK (oom_killed IN (0, 1))"
ensure_col builds sample_backend "TEXT CHECK (sample_backend IN ('cgroup', 'proc'))"
ensure_col builds sample_ncpu "INTEGER"
ensure_col builds peak_tmpfs_kb "INTEGER"
ensure_col builds product_config_toml "TEXT"
ensure_col workers disk_free_kb "INTEGER"
ensure_col workers resource_caps "INTEGER"
ensure_col worker_telemetry_samples disk_free_kb "INTEGER"

# ---- 建表建索引 ----
log_info "建 package_resource_profiles 表与索引…"
if has_table package_resource_profiles; then
    log_info "  跳过（已存在）: package_resource_profiles"
else
    # DDL 逐字抄自 baseline（schema.sql 同名表）；IF NOT EXISTS 为幂等加缀
    sq "CREATE TABLE IF NOT EXISTS package_resource_profiles (
        product TEXT NOT NULL,
        source_name TEXT NOT NULL,
        arch TEXT NOT NULL,
        declared_min_mem_kb INTEGER,
        declared_min_ncpu INTEGER,
        declared_min_disk_kb INTEGER,
        declared_updated_at TEXT,
        learned_ema_mem_kb INTEGER,
        learned_max_mem_kb INTEGER,
        learned_ema_tmpfs_kb INTEGER,
        learned_max_tmpfs_kb INTEGER,
        learned_ema_ncpu REAL,
        learned_max_ncpu REAL,
        learned_samples INTEGER NOT NULL DEFAULT 0,
        learned_sample_ncpu INTEGER,
        learned_backend TEXT CHECK (learned_backend IN ('cgroup', 'proc')),
        learned_censored INTEGER NOT NULL DEFAULT 0 CHECK (learned_censored IN (0, 1)),
        learned_updated_at TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        PRIMARY KEY (product, source_name, arch)
    )" || die "建表失败: package_resource_profiles"
    log_info "  已建表: package_resource_profiles"
    # 空表重建后必须让一次性回填重跑，否则标记仍会跳过学习面播种。
    sq "DELETE FROM app_meta WHERE key = 'resource_profiles_backfilled_at'" \
        || die "清除画像回填标记失败"
    log_info "  已清除回填标记（重启后从 builds 历史重建学习面）"
fi
# 索引独立判断：表已存在但索引缺失的库（如建表中途中断）也要补上
if has_index idx_profiles_product_mem; then
    log_info "  跳过（已存在）: idx_profiles_product_mem"
else
    sq "CREATE INDEX IF NOT EXISTS idx_profiles_product_mem ON package_resource_profiles(product, learned_ema_mem_kb)" \
        || die "建索引失败: idx_profiles_product_mem"
    log_info "  已建索引: idx_profiles_product_mem"
fi

# ---- task_labels 表与索引 ----
log_info "建 task_labels 表与索引…"
if has_table task_labels; then
    log_info "  跳过（已存在）: task_labels"
else
    sq "CREATE TABLE IF NOT EXISTS task_labels (
        task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        PRIMARY KEY (task_id, key)
    )" || die "建表失败: task_labels"
    log_info "  已建表: task_labels"
fi
if has_index idx_task_labels_key_value; then
    log_info "  跳过（已存在）: idx_task_labels_key_value"
else
    sq "CREATE INDEX IF NOT EXISTS idx_task_labels_key_value ON task_labels(key, value)" \
        || die "建索引失败: idx_task_labels_key_value"
    log_info "  已建索引: idx_task_labels_key_value"
fi
if has_index idx_builds_srpm_sha256; then
    log_info "  跳过（已存在）: idx_builds_srpm_sha256"
else
    sq "CREATE INDEX IF NOT EXISTS idx_builds_srpm_sha256 ON builds(canonical_srpm_sha256) WHERE canonical_srpm_sha256 IS NOT NULL" \
        || die "建索引失败: idx_builds_srpm_sha256"
    log_info "  已建索引: idx_builds_srpm_sha256"
fi

# ---- 存量表补 tmpfs 两列 ----
# 表已由上一步保证在位；旧脚本/旧版本建的 18 列表补 tmpfs 两列，新表已含跳过。
log_info "补 package_resource_profiles tmpfs 两列…"
ensure_col package_resource_profiles learned_ema_tmpfs_kb "INTEGER"
ensure_col package_resource_profiles learned_max_tmpfs_kb "INTEGER"

# ---- 核对 ----
log_info "核对…"
fail=0
while read -r t c; do
    if has_col "$t" "$c"; then
        log_info "  OK: $t.$c"
    else
        log_error "  缺失: $t.$c"
        fail=1
    fi
done <<'COLS'
builds req_min_mem_kb
builds req_min_ncpu
builds req_min_disk_kb
builds peak_total_kb
builds disk_wbytes
builds oom_killed
builds sample_backend
builds sample_ncpu
builds peak_tmpfs_kb
builds product_config_toml
workers disk_free_kb
workers resource_caps
worker_telemetry_samples disk_free_kb
package_resource_profiles source_name
package_resource_profiles learned_ema_tmpfs_kb
package_resource_profiles learned_max_tmpfs_kb
COLS
for obj in package_resource_profiles:table idx_profiles_product_mem:index \
           task_labels:table idx_task_labels_key_value:index idx_builds_srpm_sha256:index; do
    name=${obj%%:*} kind=${obj##*:}
    if [[ $kind == table ]] && has_table "$name"; then
        log_info "  OK: $name"
    elif [[ $kind == index ]] && has_index "$name"; then
        log_info "  OK: $name"
    else
        log_error "  缺失: $name"
        fail=1
    fi
done
[[ $fail -eq 0 ]] || die "核对未通过：上列对象仍缺失"

log_info "完成：schema 升级对象全部就位（重启 crbs-server / crbs-worker 生效）"
