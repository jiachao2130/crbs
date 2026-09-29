# CRBS RPM 打包指南

本文说明如何为 CRBS workspace 构建 RPM 包。当前版本：`0.1.0`。

## 1 包结构

| 包名 | 内容 | 说明 |
|---|---|---|
| `crbs` | CLI 二进制、示例配置、`crbs` 系统组、状态目录 | 必须安装；可独立用于本地构建 |
| `crbs-server` | server 二进制、`server.toml` 示例、systemd service、备份 unit 与脚本 | 可选；用于远端 hub 或本地 daemon；依赖 `crbs` |
| `crbs-worker` | worker 二进制、worker systemd service | 可选；用于分布式构建节点；依赖 `crbs` |
| `crbs-priv-helper` | setuid-root 特权 helper | 独立子包；`crbs` 为弱依赖，`crbs-server` / `crbs-worker` 为硬依赖 |

打包文件位于 `packaging/`：systemd units、sysusers 片段、预生成 shell 补全。仓库根目录的 `crbs.spec` 为 RPM spec，`scripts/build-srpm.sh` 用于生成 SRPM。

spec 默认启用 PostgreSQL 后端（`%bcond postgres 1`）；轻量 SQLite 部署可用 `--without postgres` 构建。

## 2 构建依赖

```bash
sudo dnf install -y rpm-build rust cargo gcc systemd-rpm-macros pkgconfig(sqlite3)
```

SRPM 不含 vendored 依赖。`rpmbuild --rebuild` 时 `%build` 按 `Cargo.lock` 拉取依赖并编译（需访问 crates.io 或配置 cargo 源镜像）。生成 SRPM 的机器只需 `rpm-build`。

`crbs-server` 默认启用 `tls` feature，产物原生支持 HTTPS，无需额外指定。

## 3 构建 RPM

### 3.1 生成 SRPM

```bash
bash scripts/build-srpm.sh
# 输出：rpmbuild/SRPMS/crbs-<version>-<release>.src.rpm

# 生成后直接送到目标机 rebuild
bash scripts/build-srpm.sh --remote user@target-host

# 保留中间目录
bash scripts/build-srpm.sh -v
```

脚本组装源码树并复制 spec，再执行 `rpmbuild -bs`。

### 3.2 从 SRPM 构建

```bash
sudo dnf install -y rpm-build rust cargo gcc systemd-rpm-macros pkgconfig(sqlite3)
rpmbuild --rebuild rpmbuild/SRPMS/crbs-0.1.0-1*.src.rpm
```

rebuild 主机需能访问 crates.io，或已配置可用的 cargo 源镜像。

产物位于 `~/rpmbuild/RPMS/<arch>/`：

```text
crbs-0.1.0-1.<dist>.<arch>.rpm
crbs-server-0.1.0-1.<dist>.<arch>.rpm
crbs-worker-0.1.0-1.<dist>.<arch>.rpm
crbs-priv-helper-0.1.0-1.<dist>.<arch>.rpm
```

### 3.3 手动准备源码包

```bash
VERSION=0.1.0
SRC_DIR="$HOME/crbs-${VERSION}-src"
rm -rf "$SRC_DIR" && mkdir -p "$SRC_DIR"

git archive --prefix="crbs-${VERSION}-src/" --format=tar HEAD | tar -C "$HOME" -xf -

cd "$HOME"
tar --exclude='.git' --exclude='target' --exclude='rpmbuild' \
    -czf "crbs-${VERSION}.tar.gz" "crbs-${VERSION}-src"

mkdir -p ~/rpmbuild/{SOURCES,SPECS,BUILD,RPMS,SRPMS}
cp "$HOME/crbs-${VERSION}.tar.gz" ~/rpmbuild/SOURCES/
cp crbs.spec ~/rpmbuild/SPECS/
cd ~/rpmbuild && rpmbuild -ba SPECS/crbs.spec
```

## 4 安装与配置

```bash
# 本地编包
sudo dnf install -y ./crbs-0.1.0-1.*.x86_64.rpm

# 远端 hub 或本地 daemon
sudo dnf install -y ./crbs-server-0.1.0-1.*.x86_64.rpm

# 分布式 worker 节点
sudo dnf install -y ./crbs-worker-0.1.0-1.*.x86_64.rpm
```

安装过程会：

- 按子包创建身份：`crbs` 组由 base 包创建；`crbs-server` / `crbs-worker` 用户由对应子包创建并加入 `crbs` 组。
- 创建 `/var/lib/crbs`（`root:crbs`，`2770`，setgid）；`crbs-server` 首次启动时将 owner 修正为 `crbs-server:crbs`。
- 安装 systemd units，但不自动启动。

将用户加入 `crbs` 组：

```bash
sudo usermod -aG crbs <username>   # 重新登录生效
```

启用 server：

```bash
sudo cp /etc/crbs/server.toml.example /etc/crbs/server.toml
sudo systemctl daemon-reload
sudo systemctl enable --now crbs-server
```

TLS、监听地址、认证与管理员初始化见 [`../docs/manual/deploy.md`](../docs/manual/deploy.md) §2–§5。

本地 daemon 模式：

```bash
crbs build pkg.src.rpm -p fedora --daemon
```

或在 `server.toml` 中设 `[local].daemon_auto = true`。默认 `auth_enabled = true`，daemon 的构建端点同样需要有效 token。

## 5 注意事项

1. **setuid helper**：`crbs-priv-helper` 通过 `%attr(4750, root, crbs)` 设置 setuid，用于创建 chroot/nspawn 容器与挂载 overlayfs；`crbs` 主程序本身不具 setuid。
2. **debuginfo**：`profile.release.strip = true` 已剥离符号表，spec 设置 `%global debug_package %{nil}` 以避免空 debuginfo 包。
3. **依赖拉取**：`%build` 按 `Cargo.lock` 拉取依赖并编译；无外网环境需为 rebuild 主机的 cargo 配置可用镜像或预填充 registry 缓存。
4. **服务身份**：`crbs-server` 与 `crbs-worker` 均以非 root 用户运行；容器所需 capability 由 priv-helper 的 setuid 机制提供。
5. **热修**：同版本重装使用 `rpm -Uvh --replacepkgs`；升级不会自动重启服务。
