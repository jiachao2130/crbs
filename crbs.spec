# CRBS RPM spec.
# Build: rpmbuild -ba crbs.spec
# From SRPM: rpmbuild --rebuild crbs-<version>-<release>.src.rpm
#
# 源码包不含 vendor：%build 按 Cargo.lock 拉取依赖并编译。
# 根 Cargo.toml 的 version 是唯一版本源，本 spec 的 Version 镜像之。

%global debug_package %{nil}

# PostgreSQL 后端默认启用；纯 SQLite 部署可用 --without postgres。
%bcond postgres 1

Name:           crbs
Version:        0.1.0
Release:        1%{?dist}
Summary:        Modern RPM batch build engine

License:        MulanPSL-2.0
URL:            https://gitcode.com/jiachao2130/crbs.git
Source0:        %{name}-%{version}.tar.gz

# Rust toolchain
BuildRequires:  rust >= 1.82
BuildRequires:  cargo
BuildRequires:  gcc
# libsqlite3-sys 经 pkg-config 动态链接系统 sqlite
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  systemd-rpm-macros

# Runtime deps
Requires:       sqlite-libs
Requires:       dnf
Requires:       rpm
Requires:       createrepo_c
Requires:       /usr/bin/systemd-nspawn
Recommends:     rpm-build
# CLI 提权经 priv-helper；缺失不阻断安装，故弱依赖（server/worker 为硬依赖）
Recommends:     %{name}-priv-helper = %{version}-%{release}

%description
CRBS is a modern RPM batch build engine supporting chroot/nspawn backends,
shared dependency layers, incremental caching, and a client/server model
for both local and remote builds.

%package server
Summary:        HTTP API server for CRBS
Requires:       %{name} = %{version}-%{release}
Requires:       %{name}-priv-helper = %{version}-%{release}
Requires:       sqlite-libs
%{?systemd_requires}
%description server
The crbs-server daemon exposes CRBS build capabilities over a RESTful HTTP
API. It can run as a local daemon or a centralized remote builder.

%package worker
Summary:        Distributed build worker for CRBS
Requires:       %{name} = %{version}-%{release}
Requires:       %{name}-priv-helper = %{version}-%{release}
%{?systemd_requires}
%description worker
The crbs-worker daemon connects to a crbs-server Hub and executes build tasks
on remote worker nodes. It supports multi-architecture builds and reports
results back to the Hub.

%package priv-helper
Summary:        Privileged helper for CRBS
Requires:       %{name} = %{version}-%{release}
%description priv-helper
The crbs-priv-helper is a small setuid-root helper that performs a limited
set of privileged operations (mount, chroot, container spawn, dnf installroot)
on behalf of the main crbs and crbs-server processes.

%prep
%setup -q -n %{name}-%{version}-src

%build
# rpmbuild 会把 spec 脚本作为 stdin 传给 cargo，rustc 读到非 UTF-8 输入会失败
exec < /dev/null

# 按 Cargo.lock 拉取依赖并编译（可使用本机配置的 cargo 镜像）。
cargo build --release --locked --workspace%{?with_postgres: --features crbs-core/postgres,crbs-server/postgres}

# crbs-normalize 全静态构建，供引擎注入任意 libc 的产品沙箱。
# x86_64 须 -no-pie：crt-static 默认产出 static-pie，自重定位在部分 CPU 上启动即段错误。
RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-no-pie -C link-arg=-static -C link-arg=-lpthread -C link-arg=-ldl" \
    cargo build --release --locked -p crbs-normalize

%install
install -D -m 0755 target/release/crbs       %{buildroot}%{_bindir}/crbs
install -D -m 0755 target/release/crbs-server %{buildroot}%{_bindir}/crbs-server
install -D -m 0755 target/release/crbs-worker %{buildroot}%{_bindir}/crbs-worker
# 全静态二进制：由引擎注入任意 libc 的产品沙箱执行（见 %build 尾部静态构建步）
install -D -m 0755 target/release/crbs-normalize %{buildroot}%{_libexecdir}/crbs/crbs-normalize
install -D -m 4750 target/release/crbs-priv-helper %{buildroot}%{_libexecdir}/crbs/crbs-priv-helper

# Configuration examples
install -D -m 0644 examples/config/crbs.toml   %{buildroot}%{_sysconfdir}/crbs/crbs.toml.example
install -D -m 0644 examples/config/server.toml %{buildroot}%{_sysconfdir}/crbs/server.toml.example
install -D -m 0644 examples/config/worker.toml %{buildroot}%{_sysconfdir}/crbs/worker.toml.example

# priv-helper 默认配置（%%config(noreplace)：升级保留管理员修改）
install -D -m 0640 examples/config/priv-helper.toml %{buildroot}%{_sysconfdir}/crbs/priv-helper.toml

# State directory (permissions enforced by %%attr in %%files)
install -d -m 0755 %{buildroot}%{_sharedstatedir}/crbs
install -d -m 0755 %{buildroot}%{_sysconfdir}/crbs/products

# systemd services（backup 定时任务归 server 子包，脚本按 libexec 约定落位）
install -D -m 0644 packaging/crbs-server.service %{buildroot}%{_unitdir}/crbs-server.service
install -D -m 0644 packaging/crbs-worker.service %{buildroot}%{_unitdir}/crbs-worker.service
install -D -m 0644 packaging/crbs-backup.service %{buildroot}%{_unitdir}/crbs-backup.service
install -D -m 0644 packaging/crbs-backup.timer   %{buildroot}%{_unitdir}/crbs-backup.timer
install -D -m 0755 deploy/backup-crbs.sh         %{buildroot}%{_libexecdir}/crbs/backup-crbs.sh

# sysusers：身份按子包拆分——组归 base，server/worker 用户归各自子包
install -D -m 0644 packaging/crbs.sysusers        %{buildroot}%{_sysusersdir}/crbs.conf
install -D -m 0644 packaging/crbs-server.sysusers %{buildroot}%{_sysusersdir}/crbs-server.conf
install -D -m 0644 packaging/crbs-worker.sysusers %{buildroot}%{_sysusersdir}/crbs-worker.conf

# Shell completions
install -d %{buildroot}%{_datadir}/bash-completion/completions
install -d %{buildroot}%{_datadir}/zsh/site-functions
install -d %{buildroot}%{_datadir}/fish/vendor_completions.d
%{buildroot}%{_bindir}/crbs completions bash > %{buildroot}%{_datadir}/bash-completion/completions/crbs
%{buildroot}%{_bindir}/crbs completions zsh > %{buildroot}%{_datadir}/zsh/site-functions/_crbs
%{buildroot}%{_bindir}/crbs completions fish > %{buildroot}%{_datadir}/fish/vendor_completions.d/crbs.fish
%{buildroot}%{_bindir}/crbs-server completions bash > %{buildroot}%{_datadir}/bash-completion/completions/crbs-server
%{buildroot}%{_bindir}/crbs-server completions zsh > %{buildroot}%{_datadir}/zsh/site-functions/_crbs-server
%{buildroot}%{_bindir}/crbs-server completions fish > %{buildroot}%{_datadir}/fish/vendor_completions.d/crbs-server.fish
%{buildroot}%{_bindir}/crbs-worker completions bash > %{buildroot}%{_datadir}/bash-completion/completions/crbs-worker
%{buildroot}%{_bindir}/crbs-worker completions zsh > %{buildroot}%{_datadir}/zsh/site-functions/_crbs-worker
%{buildroot}%{_bindir}/crbs-worker completions fish > %{buildroot}%{_datadir}/fish/vendor_completions.d/crbs-worker.fish

%pre
# Ensure the crbs group exists before installing setuid binaries.
groupadd -r crbs 2>/dev/null || :

%post
# Fix SELinux contexts for setuid binary and config/state dirs on enforcing systems.
if [ -x /sbin/restorecon ]; then
    /sbin/restorecon %{_bindir}/crbs %{_bindir}/crbs-server %{_bindir}/crbs-worker %{_libexecdir}/crbs/crbs-normalize %{_libexecdir}/crbs/crbs-priv-helper %{_sysconfdir}/crbs %{_sharedstatedir}/crbs %{_sysusersdir}/crbs.conf 2>/dev/null || true
fi

# 升级场景：旧版本可能把数据目录设成其他权限；确保只读命令（WAL）能正常写回。
if [ -d %{_sharedstatedir}/crbs ]; then
    chown root:crbs %{_sharedstatedir}/crbs 2>/dev/null || true
    chmod 2770 %{_sharedstatedir}/crbs 2>/dev/null || true
fi

# server 子包的 systemd 钩子
%post server
%systemd_post crbs-server.service
%systemd_post crbs-backup.timer

%preun server
%systemd_preun crbs-server.service
%systemd_preun crbs-backup.timer

%postun server
# 升级不自动重启：会中断活跃构建，需先排空。timer 遵循同一策略。
%systemd_postun crbs-server.service
%systemd_postun crbs-backup.timer

# worker 子包的 systemd 钩子
%post worker
%systemd_post crbs-worker.service

%preun worker
%systemd_preun crbs-worker.service

%postun worker
%systemd_postun crbs-worker.service

# 首次升级时恢复管理员配置：旧版本未把配置纳入包管理，rpm 会将其挪为
# .rpmsave 并装上纯注释的默认文件；检测到该情况则还原原配置。
%post priv-helper
p=%{_sysconfdir}/crbs/priv-helper.toml
if [ -f "$p.rpmsave" ] && ! grep -qE '^[[:space:]]*[^#[:space:]]' "$p" 2>/dev/null; then
    mv -f "$p.rpmsave" "$p"
fi

%files
%license LICENSE
%doc README.md CHANGELOG.md
%attr(0750,root,crbs) %{_bindir}/crbs
# 归一化 helper 由引擎读出注入沙箱，容器内 builder 需 o+rx，固定 0755
%attr(0755,root,root) %{_libexecdir}/crbs/crbs-normalize
%config(noreplace) %{_sysconfdir}/crbs/crbs.toml.example
%attr(0750,root,crbs) %dir %{_sysconfdir}/crbs
%attr(0750,root,crbs) %dir %{_sysconfdir}/crbs/products
# 属主 root:crbs 为骨架初值；运行时首启由 crbs-server 收敛为 crbs-server:crbs（2770 setgid 不变）
%attr(2770,root,crbs) %dir %{_sharedstatedir}/crbs
# 身份定义不是管理员配置，不加 %config(noreplace)
%{_sysusersdir}/crbs.conf
%{_datadir}/bash-completion/completions/crbs
%{_datadir}/zsh/site-functions/_crbs
%{_datadir}/fish/vendor_completions.d/crbs.fish

%files server
%doc packaging/PACKAGING.md
%attr(0750,root,crbs) %{_bindir}/crbs-server
%config(noreplace) %{_sysconfdir}/crbs/server.toml.example
%{_unitdir}/crbs-server.service
%{_unitdir}/crbs-backup.service
%{_unitdir}/crbs-backup.timer
%attr(0755,root,root) %{_libexecdir}/crbs/backup-crbs.sh
%{_sysusersdir}/crbs-server.conf
%{_datadir}/bash-completion/completions/crbs-server
%{_datadir}/zsh/site-functions/_crbs-server
%{_datadir}/fish/vendor_completions.d/crbs-server.fish

%files worker
%doc packaging/PACKAGING.md
%attr(0750,root,crbs) %{_bindir}/crbs-worker
%config(noreplace) %{_sysconfdir}/crbs/worker.toml.example
%{_unitdir}/crbs-worker.service
%{_sysusersdir}/crbs-worker.conf
%{_datadir}/bash-completion/completions/crbs-worker
%{_datadir}/zsh/site-functions/_crbs-worker
%{_datadir}/fish/vendor_completions.d/crbs-worker.fish

%files priv-helper
%attr(4750,root,crbs) %{_libexecdir}/crbs/crbs-priv-helper
%config(noreplace) %attr(0640,root,crbs) %{_sysconfdir}/crbs/priv-helper.toml

%changelog
* Fri Nov 06 2026 Jia Chao <jiachao2130@126.com> - 0.1.0-1
- Initial 0.1.0 release
- Local and distributed Hub/Worker builds with chroot and systemd-nspawn backends
- OverlayFS incremental builds, shared dependency layers, DNF cache and ccache
- Product ACL, deterministic builds, Web UI, SQLite and PostgreSQL backends
