# sw_64（申威）离线构建指南

在无外网的申威机器（CUOS 4.0 / openEuler 系，rustc/cargo 1.82.0，host 三元组
`sw_64-sunway-linux-gnu`）上离线构建 crbs 的完整方案。方案参照
`~/Gits/cuap-flow/patches/README-sw64.md`，并在其基础上适配与扩展。

## 方案概览

1. **vendor**：`vendor/` 目录由 `cargo vendor` 生成（约 330 项，与 Cargo.lock 成对）。
2. **补丁**：`patches/` 下 7 个 `.patch` 文件，路径相对源码根（`vendor/<crate>/...`），
   由 `crbs.spec` 的 `Patch1..Patch7` + `%autosetup -p1` 在 %prep 阶段自动应用；
   非 sw64 架构应用后为无操作（全部 `#[cfg(target_arch = "sw64")]` 门控），
   SRPM 四架构通用。补丁不携带 checksum 变更。
3. **checksum**：patched/pristine vendor 均使用空表 checksum
   `{"files":{},"package":"<Cargo.lock 的 sha256>"}`——cargo 目录源据此跳过文件级
   校验，`--locked` 的 package 级校验仍可用。注意 cargo >= 1.9x 的 registry src
   目录不再落盘 `.cargo-checksum.json`，pristine 化后必须补写。
4. **一键脚本**：`scripts/build-srpm.sh` 完成 vendor 同步 → 补丁应用 → 本地验证 →
   打包树组装（pristine vendor + `.cargo/config.toml` vendored 替换）→ SRPM 生成，
   补丁清单从 spec 的 `PatchN` 行解析；可选 `--remote USER@HOST` 直接在目标机
   `rpmbuild --rebuild` 真机验证。
5. **构建**（SRPM rebuild 或手动）：
   ```bash
   cargo build --release --offline --locked --workspace \
     --features crbs-core/bundled-sqlite,crbs-core/postgres,crbs-server/postgres
   ```

## 各补丁内容

| 补丁 | crate | 内容 |
|---|---|---|
| `libc-0.2.186-sw64.patch` | libc 0.2.186 | sw64 架构支持，移植自 openEuler `src-openeuler/rust` 的 sw64 补丁（cuap-flow 版针对 0.2.175，本版适配 0.2.186）。含 arch/gnu/b64 三层模块、alpha 系 errno/signal/termios/socket 常量、termios2 结构等 |
| `linux-raw-sys-0.12.1-sw64.patch` | linux-raw-sys 0.12.1 | 新增 `src/sw64/{general,ioctl}.rs`（基于 riscv64/asm-generic 版，125 个常量按申威机器实测值修正）+ lib.rs 门控 |
| `linux-raw-sys-0.4.15-sw64.patch` | linux-raw-sys 0.4.15 | 同上（rustix 0.38 的依赖） |
| `rustix-1.1.4-sw64.patch` | rustix 1.1.4 | ioctl 编码分组把 sw64 归入 mips 风格组（NONE=1/READ=2/WRITE=4/SIZE_BITS=13/DIR_BITS=3） |
| `rustix-0.38.44-sw64.patch` | rustix 0.38.44 | 同上 |
| `caps-0.5.6-sw64.patch` | caps 0.5.6 | sw64 系统调用号 CAPGET=368/CAPSET=369（alpha 表） |
| `nix-0.29.0-sw64.patch` | nix 0.29.0 | statfs 字段 i64→按返回类型 cast；SIGSTKFLT 相关 5 处 cfg 排除 sw64（sw64 无此信号）；30 信号数组分派加 sw64 |

## 关键事实（踩坑记录）

1. **`target_arch` 的 cfg 值是 `sw64`，不带下划线**。host 三元组
   `sw_64-sunway-linux-gnu` 带下划线，但 `rustc --print cfg` 输出
   `target_arch="sw64"`。写错拼写的 cfg 永不命中且编译照常通过——运行期常量
   全部静默取错，极难排查。
2. **申威是 alpha 系 ABI，与 asm-generic 差异巨大**（已全部按目标机
   `gcc -E -dM` 实测核对）：
   - errno：EAGAIN=35、EDEADLK=11、ELOOP=62、ENOSYS=78、ESTALE=70……
     （libc 0.2.186 中这批常量在 `linux_l4re_shared.rs`，以 glob re-export
     并入 linux-gnu，不能在 `linux/mod.rs` 直接加同名常量，会产生 glob 歧义）
   - 信号：SIGURG=16、SIGCHLD=20、SIGUSR1=30、7=SIGEMT、29=SIGINFO，
     **无 SIGSTKFLT/SIGUNUSED**
   - O_*：O_APPEND=8、O_NONBLOCK=4、O_CREAT=512……（fcntl 编号整表不同）
   - termios：CBAUD=31、CS8=0x300、V* 下标、B* 波特率全部不同
   - ioctl 编码：mips 风格（SIZEBITS=13、DIRBITS=3、NONE=1、READ=2、WRITE=4）
   - 系统调用号：capget=368、capset=369、openat=450、openat2=284（alpha 表）
   - TCSETS2/TCSETSW2/TCSETSF2 未随内核头导出，按 TCGETS2=0x802c542a 的编码
     规则推导为 0x4002542b/c/d（nr 2b/2c/2d、WRITE=4<<30、size 44<<16）
3. **c_char 是有符号的**（`gcc -E -dM` 无 `__CHAR_UNSIGNED__`）→ c_char=i8，
   libc 默认值正确，linux-raw-sys 的 ctypes 需把 sw64 归入 c_schar 组。
4. **多版本 crate**：lock 中同名 crate 多版本共存（如 getrandom 0.2.17 与
   0.3.4），vendor 中以 `vendor/<name>-<version>` 目录存放，传输/清理时不可删。
5. **rustix 在 sw64 走 libc 后端**（linux_raw 后端的架构白名单不含 sw64），
   无需 asm 支持；ring 0.17 走纯 C 回退（无 sw64 汇编），blake3 走纯 Rust，
   均可直接编译。
6. **改 vendored crate 后 cargo 可能不重编**（fingerprint 缓存），验证前先
   `cargo clean -p <crate>`。注意 `-p rustix-0.38.44` 是非法包名（含 `.`），
   要写 `-p rustix`。
7. 环境无需 openssl-devel / libpq：TLS 走 rustls+ring，PostgreSQL 走 sqlx
   纯 Rust 实现。

## sw64 ld 链接崩溃与 LTO 取舍（2026-10-06）

现象：0.1.0 代码 + postgres feature 下，thin LTO 链接大二进制时 GNU ld 堆损坏
崩溃（corrupted size vs. prev_size, signal 6），4/4 稳定复现（rpmbuild + 手工
全量 + 增量重试 ×2，跨内存布局，非偶发）。

归因：链接输入规模越过 sw64 ld 后端（alpha 系移植，与 x86_64 主干是不同的
代码路径）越界写 bug 的临界点——crates 源码 99,967 行（老代码 1.0.0-rc1，
同 features 构建成功）→ 244,361 行（2.44×），叠加 sqlx-postgres 引入的
rsa/num-bigint-dig 大 object。与机器负载无关：ld 单线程，进程内堆布局由
输入内容的分配序列唯一决定，负载只影响速度。

- 方案 A `--no-keep-memory`：链接可完成但极慢（crbs 单二进制 ~35 分钟，
  全链预计 1.5-2h/次重打），产物质量无损但时间成本不可用，弃用
- 方案 B（采用）`CARGO_PROFILE_RELEASE_LTO=off`（spec `%ifarch sw_64` 段）：
  全量 11m47s；代价为 sw64 二进制无跨 crate 内联优化，IO 密集服务影响可忽略
- 根治：向 openEuler/申威反馈 ld bug（复现现成：0.1.0 代码 + features），
  binutils/lld 更新后删 spec `%ifarch sw_64` 段即恢复 LTO

## 验证记录

- 2026-09-10：~/crbs 手工流程（老代码 1.0.0-rc1 + postgres features），
  `cargo build --release` 230 crate 9m57s，四二进制冒烟 ✓
- 2026-10-06：`scripts/build-srpm.sh` 产出自包含
  `crbs-0.1.0-1.src.rpm`（tarball 含 pristine vendor + `.cargo/config.toml`），
  sw_64 / aarch64 / x86_64 / loongarch64 四台真机 `rpmbuild --rebuild` 全部走通
  %prep（%autosetup 应用 7 补丁）→ %build（vendored 离线，postgres 默认启用，
  sw64 关 LTO）→ %install，各产出四个 `0.1.0-1.ule4.<arch>` RPM ✓
- 2026-10-07：五机部署（80.7 Hub + PG，80.1/2/4/7/20 五 worker 全 online），
  产品 ule3/ule4 配置完成，vim 首测构建四架构 SUCCEEDED ✓

## 真机 rebuild 命令

```bash
rpmbuild --rebuild --define "_topdir $HOME/rpmbuild" crbs-0.1.0-2.src.rpm
# _topdir 必须是展开后的绝对路径；rpm 宏本身不展开 ~
```

## 与上游 libc 补丁的差异说明

cuap-flow 的 `libc-0.2.175-sw64.patch` 适配到 0.2.186 时，三个 hunk 因上游
重构（errno/MAP/POSIX_MADV 常量移入 `linux_l4re_shared.rs`）无法套用，已按
0.2.186 布局重写；其余 hunk 原样套用。0.2.175→0.2.186 之间被上游移入 per-arch
文件的常量已逐一核对，sw64.rs 现有内容与目标机实测值一致。
