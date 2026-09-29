#!/bin/bash
# crbs 一键部署脚本
# 用法: sudo ./scripts/setup.sh [用户名 ...]
# 示例: sudo ./scripts/setup.sh alice bob
#   无参数时只安装二进制和配置权限，不添加用户
set -euo pipefail

CLI_BINARY="crbs"
SERVER_BINARY="crbs-server"
HELPER_BINARY="crbs-priv-helper"
INSTALL_DIR="/usr/local/bin"
HELPER_DIR="/usr/libexec/crbs"
DATA_DIR="/var/lib/crbs"
GROUP_NAME="crbs"

if [ "$(id -u)" -ne 0 ]; then
    echo "错误：请以 root 运行此脚本 (sudo ./scripts/setup.sh)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CLI_PATH="$INSTALL_DIR/$CLI_BINARY"
SERVER_PATH="$INSTALL_DIR/$SERVER_BINARY"
HELPER_PATH="$HELPER_DIR/$HELPER_BINARY"

echo "=== crbs 部署 ==="

# 确保 crbs 组存在（install -g 需要组已创建）
if ! getent group "$GROUP_NAME" > /dev/null 2>&1; then
    groupadd -r "$GROUP_NAME"
fi

# 1. 构建
if [ -f "$PROJECT_DIR/Cargo.toml" ]; then
    if ! command -v cargo &>/dev/null; then
        echo "错误：未找到 cargo，请先安装 Rust 工具链: https://rustup.rs" >&2
        exit 1
    fi
    echo "[1/6] 构建 workspace release 二进制..."
    cargo build --release --manifest-path "$PROJECT_DIR/Cargo.toml"
    CLI_SRC="$PROJECT_DIR/target/release/$CLI_BINARY"
    SERVER_SRC="$PROJECT_DIR/target/release/$SERVER_BINARY"
    HELPER_SRC="$PROJECT_DIR/target/release/$HELPER_BINARY"
else
    CLI_SRC="$(command -v "$CLI_BINARY" 2>/dev/null || true)"
    SERVER_SRC="$(command -v "$SERVER_BINARY" 2>/dev/null || true)"
    HELPER_SRC="$(command -v "$HELPER_BINARY" 2>/dev/null || true)"
    if [ -z "$CLI_SRC" ] || [ -z "$SERVER_SRC" ] || [ -z "$HELPER_SRC" ]; then
        echo "错误：找不到 $CLI_BINARY/$SERVER_BINARY/$HELPER_BINARY 二进制，请在项目目录运行或预先安装" >&2
        exit 1
    fi
    echo "[1/6] 使用已安装的二进制: $CLI_SRC, $SERVER_SRC, $HELPER_SRC"
fi

# 2. 安装 CLI 二进制（不再 setuid，普通组成员可执行）
echo "[2/6] 安装 CLI 到 $CLI_PATH ..."
install -m 0750 -o root -g "$GROUP_NAME" "$CLI_SRC" "$CLI_PATH"

# 3. 安装 server 二进制
echo "[3/6] 安装 server 到 $SERVER_PATH ..."
install -m 0750 -o root -g "$GROUP_NAME" "$SERVER_SRC" "$SERVER_PATH"

# 4. 安装特权 helper（setuid root，仅同组可执行）
# helper 负责 mount/umount、chroot/nspawn、mkdir_chown 以及 dnf --installroot 等特权操作。
echo "[4/6] 安装特权 helper 到 $HELPER_PATH ..."
install -d -m 0755 -o root -g root "$HELPER_DIR"
install -m 4750 -o root -g "$GROUP_NAME" "$HELPER_SRC" "$HELPER_PATH"

# 5. 数据目录
echo "[5/6] 配置数据目录 $DATA_DIR ..."
mkdir -p "$DATA_DIR"
chown root:"$GROUP_NAME" "$DATA_DIR"
chmod 2770 "$DATA_DIR"

# 6. 配置目录（产品配置需 crbs 组成员可写）
echo "[6/6] 配置配置目录 /etc/crbs ..."
mkdir -p /etc/crbs/products
chown root:"$GROUP_NAME" /etc/crbs /etc/crbs/products
chmod 0750 /etc/crbs
chmod 0750 /etc/crbs/products

# 7. 添加用户
if [ $# -gt 0 ]; then
    echo "[7/7] 添加用户到 $GROUP_NAME 组..."
    for user in "$@"; do
        if id "$user" &>/dev/null; then
            usermod -aG "$GROUP_NAME" "$user"
            echo "  ✓ $user 已加入 $GROUP_NAME 组（需重新登录生效）"
        else
            echo "  ✗ 用户 $user 不存在，跳过" >&2
        fi
    done
else
    echo "[7/7] 未指定用户名，跳过。手动添加: usermod -aG $GROUP_NAME <username>"
fi

echo ""
echo "=== 部署完成 ==="

# 验证 helper setuid 位
if [ -u "$HELPER_PATH" ]; then
    echo "  ✓ helper setuid 位已设置"
else
    echo "  ✗ 警告：helper setuid 位未设置，非 root 用户将无法运行" >&2
fi

echo "CLI 二进制:     $CLI_PATH ($(stat -c '%a %U:%G' "$CLI_PATH"))"
echo "Server 二进制:  $SERVER_PATH ($(stat -c '%a %U:%G' "$SERVER_PATH"))"
echo "Helper 二进制:  $HELPER_PATH ($(stat -c '%a %U:%G' "$HELPER_PATH"))"
echo "数据目录:       $DATA_DIR ($(stat -c '%a %U:%G' "$DATA_DIR"))"
echo "配置目录:       /etc/crbs ($(stat -c '%a %U:%G' /etc/crbs)), /etc/crbs/products ($(stat -c '%a %U:%G' /etc/crbs/products))"
echo "组:             $GROUP_NAME ($(getent group "$GROUP_NAME"))"
echo ""
echo "用法:"
echo "  crbs build foo.src.rpm -p myproduct       # crbs 组用户直接运行"
echo "  sudo crbs build foo.src.rpm -p myproduct  # root/sudo 仍可用"
echo "  crbs status                               # 普通用户可运行"
echo "  sudo crbs-server run                      # 启动 HTTP API server"
