// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 通用工具：时间格式化、RPM 包名解析、路径校验与退避抖动等共用函数。

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{Local, NaiveDateTime, Utc};
use tokio_util::sync::CancellationToken;

use crate::error::CrbsError;

/// RPM %changelog 解析：纯函数 + `ChangelogEntry` serde 结构。
pub mod rpm_changelog;
/// DB 时间列 TEXT 帧格式（UTC 墙钟 `YYYY-MM-DD HH:MM:SS`）：与 SQLite
/// `datetime('now')` / `Dialect::sql_now` PG 分支同帧，写入与读取解析必须
/// 共用此常量——混帧会令 TEXT 词法比较错位（`'T'` > `' '`）。
pub const DB_TIME_FMT: &str = "%Y-%m-%d %H:%M:%S";

/// 解析 DB 时间列 TEXT 帧（[`DB_TIME_FMT`]，UTC 墙钟）：只认空格分隔存储
/// 帧，RFC3339 / 纯日期 → None（调用方据此透传降级）；时区感知用 `.and_utc()`。
pub fn parse_db_time(s: &str) -> Option<NaiveDateTime> {
    NaiveDateTime::parse_from_str(s, DB_TIME_FMT).ok()
}

/// 当前时间的 DB TEXT 帧字符串：把"现在"作为 bind 参数写入时间列用
///（SQL 内联生成走 `Dialect::sql_now()`），保证读写同一时间帧。
pub fn db_now_utc() -> String {
    Utc::now().format(DB_TIME_FMT).to_string()
}

/// CLI watch 模式即时本地时间显示：无 `%Z` 后缀，与 [`format_local_time`]
/// 的带 `%Z` 完整显示是两个并存变体，勿统一。
pub fn format_local_now() -> String {
    Local::now().format(DB_TIME_FMT).to_string()
}

/// DB 存储的 UTC 时间串转本地系统时区显示；解析失败原样返回降级。
/// 面向用户的时间显示统一走这里，勿硬编码时区偏移。
pub fn format_local_time(s: &str) -> String {
    if s.is_empty() || s == "-" {
        return "-".to_string();
    }
    if let Some(naive) = parse_db_time(s) {
        let local = naive.and_utc().with_timezone(&Local);
        return local.format("%Y-%m-%d %H:%M:%S %Z").to_string();
    }
    s.to_string()
}

/// half jitter 退避延迟：满值 `base * 2^(attempt-1)` 的 [1/2, 1] 区间按
/// `frac ∈ [0,1]` 取值——错开多实例同步重试（thundering herd），1/2 下界防
/// 过激重试。`attempt == 0` 按 1 处理，指数封顶 `2^31` 防下溢/溢出；与
/// `engine::retry` 的 [full, 1.5·full) 是刻意不同的两种分布（满值下界 vs
/// 上界），勿收敛。
fn half_jitter_delay(attempt: u32, base: Duration, frac: f64) -> Duration {
    let full = base * 2_u32.pow(attempt.saturating_sub(1).min(31));
    full.div_f64(2.0) + full.mul_f64(frac.clamp(0.0, 1.0) / 2.0)
}

/// 轻量随机源（退避抖动专用，非密码学）：`RandomState` 哈希密钥来自 OS
/// RNG，空输入 finish 得近似均匀分布的 u64。
fn rand_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
}

/// u64 → i64 饱和转换：`as i64` 遇 ≥ 2^63 回绕成负数——"N 天前"变未来
/// 时刻，retention GC 匹配**所有**行；饱和 i64::MAX 是保守方向（≈ 不清理），
/// 兜底未过 `require_i64_representable_u64` 校验的存量配置直连 DB 路径。
pub fn u64_to_i64_saturating(v: u64) -> i64 {
    v.min(i64::MAX as u64) as i64
}

/// 防穿越谓词：`path` 严格位于 `root` 之下且不等于 `root` 本身——teardown
/// 类操作的命名空间断言共用形态，防误删共享根。
pub fn strictly_within(path: &Path, root: &Path) -> bool {
    path.starts_with(root) && path != root
}

/// `half_jitter_delay` 的便捷包装：随机 `frac` 取自 `rand_u64`。
pub(crate) fn half_jitter_delay_now(attempt: u32, base: Duration) -> Duration {
    let frac = rand_u64() as f64 / u64::MAX as f64;
    half_jitter_delay(attempt, base, frac)
}

/// NEVRA → RPM 文件名中的包名：补 `.rpm` 后缀复用 [`extract_rpm_name`]。
pub fn rpm_name_of_nevra(nevra: &str) -> String {
    extract_rpm_name(&format!("{nevra}.rpm")).to_string()
}

/// 从 RPM/SRPM 文件名提取包名：文件名格式 `name-version-release[.arch|.src].rpm`，
/// 去后缀后取 NVR 的 name 段（[`split_nvr`]）。
pub fn extract_rpm_name(filename: &str) -> &str {
    let stem = filename
        .strip_suffix(".src.rpm")
        .or_else(|| filename.strip_suffix(".rpm"))
        .unwrap_or(filename);
    split_nvr(stem).0
}

/// 将 NVR 拆分为 (name, version, release)：从末尾取 release、version 两段，
/// name 可含连字符（`git-lfs`）；缺分隔符 → (nvr, "", "") 整体作 name。
pub fn split_nvr(nvr: &str) -> (&str, &str, &str) {
    let parts: Vec<&str> = nvr.rsplitn(3, '-').collect();
    if parts.len() >= 3 {
        (parts[2], parts[1], parts[0])
    } else {
        (nvr, "", "")
    }
}

/// 把字符串包成 shell 单引号字符串，并转义其中的单引号。
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// 控制字符转义：`\t`/`\r`/`\n` 短转义，其余 C0/DEL 用 `\xHH`，输出整体
/// 单行——不可信文本内插 tracing/审计行时 `\n` 可伪造下一条日志记录，进
/// sink 前必须过本函数（DB/UI 渲染端转义的链路不受影响）。crbs-priv-helper
/// 另有逐字同步副本：setuid 二进制刻意不依赖 crbs-core。
pub fn escape_ctrl(s: &str) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            '\x00'..='\x1f' | '\x7f' => {
                // match 范围保证 c <= 0x7f，`as u8` 截断无损。
                let _ = write!(out, "\\x{:02x}", c as u8);
            }
            _ => out.push(c),
        }
    }
    out
}

/// 稳态循环的连续失败告警节流：首败告警，此后每第 `every` 次连续失败再
/// 告警；成功复位。秒级 tick 循环持续故障时防刷屏、也保留再次故障第一现场。
#[derive(Debug)]
pub struct WarnThrottle {
    consecutive: u64,
    every: u64,
}

impl WarnThrottle {
    /// `every` 为连续失败之间的告警间隔（1 = 每次失败都告警）。
    pub fn new(every: u64) -> Self {
        Self {
            consecutive: 0,
            every: every.max(1),
        }
    }

    /// 记录一次失败，返回本次是否应输出告警。
    pub fn fail(&mut self) -> bool {
        self.consecutive += 1;
        self.consecutive == 1 || self.consecutive % self.every == 0
    }

    /// 当前连续失败计数（告警字段用）。
    pub fn consecutive(&self) -> u64 {
        self.consecutive
    }

    /// 记录一次成功，复位连续失败计数。
    pub fn reset(&mut self) {
        self.consecutive = 0;
    }
}

/// 判断进程是否存活：`getpgid` 查存在性 + `/proc` comm/cmdline 名称校验
/// 防 PID 复用误判；不发送任何信号。非 Linux 无 /proc，仅存在性判断。
pub async fn is_process_alive(pid: i64) -> bool {
    use nix::unistd::{getpgid, Pid};
    if pid <= 0 || pid > i32::MAX as i64 {
        return false;
    }
    let pid = Pid::from_raw(pid as i32);
    if getpgid(Some(pid)).is_err() {
        return false;
    }

    // comm 仅二进制名、cmdline 含完整路径/参数，双重校验；测试二进制名为
    // crbs_core-<hash> 等，故按 `crbs` 前缀匹配。
    #[cfg(target_os = "linux")]
    {
        let pid_raw = pid.as_raw();
        // comm/cmdline 在 hidepid 等场景可能读失败；getpgid 已确认存在，按
        // 存活处理，避免 zombie reaper 误杀活进程。
        let comm = match tokio::fs::read_to_string(format!("/proc/{}/comm", pid_raw)).await {
            Ok(s) => s.trim().to_string(),
            Err(_) => return true,
        };
        if !comm.starts_with("crbs") {
            return false;
        }
        let cmdline = match tokio::fs::read_to_string(format!("/proc/{}/cmdline", pid_raw)).await {
            Ok(s) => s,
            Err(_) => return true,
        };
        cmdline.split('\0').any(|part| {
            let p = part.trim();
            !p.is_empty() && (p.contains("/crbs") || p.starts_with("crbs"))
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

/// 从 SRPM 路径提取显示名（含版本），如 `git-lfs-3.7.1-4.fc44`。
pub fn srpm_display_name(path: &std::path::Path) -> &str {
    path.file_stem()
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_suffix(".src"))
        .unwrap_or("unknown")
}

/// 判断 64 位小写十六进制（`[0-9a-f]{64}`）：`gc::is_layer_digest` 与
/// `engine::cache` 共用的单一真值，禁止再落副本——缓存路径的 sha256 可能
/// 来自 build_packages.json / lockfile 等不可信输入，1 字符值令 `&sha[..2]`
/// 切片 panic、`../` 路径穿越，join 前必须先过。例外勿并：`by_sha256`
/// 端点预校验用 `is_ascii_hexdigit`（大小写均收，用户可持大写指纹查询）。
pub(crate) fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// 校验 SRPM 文件名派生的包名可安全用于文件系统路径与 DB 记录：拒空、
/// 路径分隔符、`\0` 与 `..`/根分量穿越。
pub fn validate_pkg_name(name: &str) -> crate::Result<()> {
    if name.is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: "package name is empty".to_string(),
        });
    }
    if name.contains('/') || name.contains('\0') {
        return Err(CrbsError::ValidationFailed {
            message: format!("package name contains illegal characters: {:?}", name),
        });
    }
    for component in std::path::Path::new(name).components() {
        match component {
            std::path::Component::ParentDir | std::path::Component::RootDir => {
                return Err(CrbsError::ValidationFailed {
                    message: format!("package name contains path traversal: {:?}", name),
                });
            }
            _ => {}
        }
    }
    Ok(())
}

/// 校验路径无 `..` 分量与 `\0`，可选要求绝对路径：供 join 进 chroot 根或
/// 受控前缀的路径用；不要求路径存在。
pub fn validate_path_no_traversal(
    path: &std::path::Path,
    require_absolute: bool,
) -> crate::Result<()> {
    let s = path.to_str().ok_or_else(|| CrbsError::ValidationFailed {
        message: format!("path is not valid UTF-8: {}", path.display()),
    })?;
    if s.contains('\0') {
        return Err(CrbsError::ValidationFailed {
            message: format!("path contains null bytes: {}", path.display()),
        });
    }
    if require_absolute && !path.is_absolute() {
        return Err(CrbsError::ValidationFailed {
            message: format!("path is not absolute: {}", path.display()),
        });
    }
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(CrbsError::ValidationFailed {
                message: format!("path contains path traversal: {}", path.display()),
            });
        }
    }
    Ok(())
}

/// RPM lead header 魔数（SRPM 文件前 4 字节 `ED AB EE DB`）：server 上传
/// 预检与 engine 侧校验的单一真值，禁止再落副本。
pub const RPM_MAGIC: [u8; 4] = [0xED, 0xAB, 0xEE, 0xDB];

/// 校验 SRPM 路径安全：绝对、无穿越、以 `.src.rpm` 结尾；不读文件——
/// 内容校验（比对 [`RPM_MAGIC`]）由调用方另行做。
pub fn validate_srpm_path(path: &std::path::Path) -> crate::Result<()> {
    validate_path_no_traversal(path, true)?;
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if !name.ends_with(".src.rpm") {
        return Err(CrbsError::ValidationFailed {
            message: format!("SRPM filename must end with .src.rpm: {}", path.display()),
        });
    }
    Ok(())
}

/// 词法规范化绝对路径（不解析 symlink，拒 `..` 逃逸）：canonicalize 因
/// 路径不存在失败时的回退，结果无 `.`/`..` 分量。
fn normalize_absolute(path: &Path) -> crate::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(CrbsError::ValidationFailed {
            message: format!("path is not absolute: {}", path.display()),
        });
    }
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            std::path::Component::RootDir => out.push("/"),
            std::path::Component::Normal(p) => out.push(p),
            std::path::Component::ParentDir => {
                if !out.pop() {
                    return Err(CrbsError::ValidationFailed {
                        message: format!("path escapes filesystem root: {}", path.display()),
                    });
                }
            }
            std::path::Component::CurDir => {}
            std::path::Component::Prefix(p) => out.push(p.as_os_str()),
        }
    }
    Ok(out)
}

/// Canonicalize `path` 并确保仍在 `root` 内；不存在时按最深已存在祖先
/// canonicalize 拼回词法后缀（见函数内注释）。穿越/相对路径 →
/// ValidationFailed，IO 错误 → Io。
pub async fn canonicalize_within(path: &Path, root: &Path) -> crate::Result<PathBuf> {
    let abs_root = tokio::fs::canonicalize(root).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CrbsError::ValidationFailed {
                message: format!("result root does not exist: {}", root.display()),
            }
        } else {
            CrbsError::from_io_context("canonicalize root", e)
        }
    })?;

    match tokio::fs::canonicalize(path).await {
        Ok(abs) => {
            if abs == abs_root || abs.starts_with(&abs_root) {
                Ok(abs)
            } else {
                Err(CrbsError::ValidationFailed {
                    message: format!("path {} escapes root {}", path.display(), root.display()),
                })
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // 纯词法 starts_with 拦不住中间目录是 symlink 的逃逸（out ->
            // /tmp/evil 后查 out/x.rpm）：最深已存在祖先 canonicalize（解析
            // symlink）确认在 root 内，再拼回 normalize 保证无 `..` 的后缀。
            let normalized = normalize_absolute(path)?;
            let mut ancestor = normalized.clone();
            let canon_ancestor = loop {
                match tokio::fs::canonicalize(&ancestor).await {
                    Ok(c) => break c,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        if !ancestor.pop() {
                            return Err(CrbsError::ValidationFailed {
                                message: format!(
                                    "path {} escapes root {}",
                                    path.display(),
                                    root.display()
                                ),
                            });
                        }
                    }
                    Err(e) => return Err(CrbsError::from_io_context("canonicalize ancestor", e)),
                }
            };
            if canon_ancestor != abs_root && !canon_ancestor.starts_with(&abs_root) {
                return Err(CrbsError::ValidationFailed {
                    message: format!("path {} escapes root {}", path.display(), root.display()),
                });
            }
            // ancestor 是 normalized 的词法前缀，strip_prefix 失败不可达（防御）。
            let suffix =
                normalized
                    .strip_prefix(&ancestor)
                    .map_err(|_| CrbsError::ValidationFailed {
                        message: format!("path {} escapes root {}", path.display(), root.display()),
                    })?;
            Ok(canon_ancestor.join(suffix))
        }
        Err(e) => Err(CrbsError::from_io_context("canonicalize", e)),
    }
}

/// 校验 DB 存的 `result_dir` 仍在配置的产品结果目录 `result_root` 内。
pub async fn validate_result_dir(result_dir: &str, result_root: &Path) -> crate::Result<PathBuf> {
    canonicalize_within(Path::new(result_dir), result_root).await
}

/// 结果目录内只读校验：必须是普通文件，symlink 一律拒绝（构建容器可预植
/// `build.log -> /etc/crbs/...`，跟随读取会把宿主文件流给查看者）。
pub async fn is_regular_file_no_symlink(path: &Path) -> bool {
    matches!(
        tokio::fs::symlink_metadata(path).await,
        Ok(m) if m.file_type().is_file()
    )
}

/// 只读打开结果目录内文件并拒绝 symlink（O_NOFOLLOW 闭合检查-打开窗口）。
pub fn open_read_no_follow() -> tokio::fs::OpenOptions {
    let mut opts = tokio::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        opts.custom_flags(nix::libc::O_NOFOLLOW);
    }
    opts
}

/// 结果目录安全写：不跟随已存在的 symlink。构建容器对 result_dir 可写，恶意
/// spec（或同一构建的上一次重试）可预植指向宿主文件的链接；`create/truncate`
/// 跟随会改写/外泄宿主文件。先删条目本身（symlink 只删链接），再 `create_new`
/// （O_EXCL）——攻击者重建链接只会让创建失败，绝不写目标。
pub async fn write_result_file_no_follow(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut f = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await?;
    tokio::io::AsyncWriteExt::write_all(&mut f, bytes).await?;
    f.sync_all().await?;
    Ok(())
}

/// 校验 `cpio -it` 成员名列表（纯函数）：拒绝对路径与 `..` 分量——cpio
/// `-id` 不清洗成员名且 `*.spec` 的 `*` 匹配含 `/`，`../evil.spec` 可写出
/// dest_dir 之外，命中 fail-closed 拒整个 SRPM。`./` 前缀（真实 RPM
/// payload 常见形态）与普通相对路径放行。
fn validate_cpio_member_names(listing: &str) -> crate::Result<()> {
    for raw in listing.lines() {
        let name = raw.trim();
        if name.is_empty() {
            continue;
        }
        if name.starts_with('/') {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "SRPM cpio member {name:?} is an absolute path; refusing to extract"
                ),
            });
        }
        if name.split('/').any(|c| c == "..") {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "SRPM cpio member {name:?} contains a '..' path component; refusing to extract"
                ),
            });
        }
    }
    Ok(())
}

/// 解包前预扫 SRPM 成员名：`rpm2cpio | cpio -it` 列全部成员逐行校验
/// （[`validate_cpio_member_names`]）。listing 上限复用 MAX_CAPTURE_BYTES，
/// 超限 fail-closed——截断列表尾部可能藏穿越成员，不能静默消费；双进程
/// 管道无法走单命令的 `run_command_capped_output*`。
async fn prescan_srpm_cpio_members(srpm: &std::path::Path) -> crate::Result<()> {
    use tokio::io::AsyncReadExt;

    let mut rpm2cpio = tokio::process::Command::new("rpm2cpio")
        .arg(srpm)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            CrbsError::io_message(format!("spawn rpm2cpio for {}: {}", srpm.display(), e))
        })?;

    let mut cpio = tokio::process::Command::new("cpio")
        .arg("-it")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| CrbsError::from_io_context("spawn cpio -it", e))?;

    let mut rpm_out = rpm2cpio
        .stdout
        .take()
        .ok_or_else(|| CrbsError::io_message("rpm2cpio stdout unavailable"))?;
    let mut cpio_in = cpio
        .stdin
        .take()
        .ok_or_else(|| CrbsError::io_message("cpio stdin unavailable"))?;
    let mut cpio_out = cpio
        .stdout
        .take()
        .ok_or_else(|| CrbsError::io_message("cpio stdout unavailable"))?;

    let cap = crate::engine::command::MAX_CAPTURE_BYTES;
    let mut listing: Vec<u8> = Vec::new();
    let mut overflow = false;
    let mut chunk = [0u8; 8192];
    // 读写两侧并发推进：串行会死锁（cpio stdout 写满管道反压阻塞 rpm2cpio）；
    // 读满 cap 后丢弃式排空防死锁，最后按 overflow fail-closed。
    let feed = async {
        let r = tokio::io::copy(&mut rpm_out, &mut cpio_in).await;
        // EOF 靠 drop 关 fd 送达：ChildStdin::shutdown() 是 no-op（管道无半关）。
        // 不 drop 的话 bsdcpio（macOS）会永远等 stdin；GNU cpio 读到 TRAILER
        // 即退出，掩盖差别。
        drop(cpio_in);
        r
    };
    let drain = async {
        loop {
            match cpio_out.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    if listing.len() + n <= cap {
                        listing.extend_from_slice(&chunk[..n]);
                    } else {
                        overflow = true;
                    }
                }
                Err(e) => {
                    return Err(CrbsError::from_io_context("read cpio -it listing", e));
                }
            }
        }
        Ok(())
    };
    let (feed_res, drain_res) = tokio::join!(feed, drain);
    feed_res.map_err(|e| CrbsError::from_io_context("pipe rpm2cpio -> cpio -it", e))?;
    drain_res?;

    let (rpm_status, cpio_status) = tokio::try_join!(rpm2cpio.wait(), cpio.wait())
        .map_err(|e| CrbsError::from_io_context("wait rpm2cpio/cpio -it", e))?;
    if !cpio_status.success() || !rpm_status.success() {
        return Err(CrbsError::io_message(format!(
            "prescan members of {} failed: rpm2cpio={:?}, cpio={:?}",
            srpm.display(),
            rpm_status.code(),
            cpio_status.code()
        )));
    }
    if overflow {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "SRPM {} member listing exceeds {} bytes; refusing to extract",
                srpm.display(),
                cap
            ),
        });
    }
    validate_cpio_member_names(&String::from_utf8_lossy(&listing)).map_err(|e| {
        CrbsError::ValidationFailed {
            message: format!("{}: {}", srpm.display(), e),
        }
    })
}

/// 从 SRPM 提取 `.spec` 到目标目录，返回 spec 路径：`rpm2cpio | cpio` 管道
///（不拼 shell 字符串），解包前先预扫成员名（防 `..` 穿越——此处以特权
/// 身份解不可信 SRPM，dest_dir 是 tmpdir）。cancel/timeout 触发时 drop
/// 子进程句柄（SIGKILL）。
pub async fn extract_spec_from_srpm(
    srpm: &Path,
    dest_dir: &Path,
    cancel_token: Option<&CancellationToken>,
    timeout: Option<Duration>,
) -> crate::Result<PathBuf> {
    let srpm = srpm.to_path_buf();
    let dest_dir = dest_dir.to_path_buf();
    let run_fut = async move {
        prescan_srpm_cpio_members(&srpm).await?;

        let mut rpm2cpio = tokio::process::Command::new("rpm2cpio")
            .arg(&srpm)
            .current_dir(&dest_dir)
            .stdout(std::process::Stdio::piped())
            // rpm2cpio 进度/警告会刷屏（chain 每 SRPM 一次），丢弃。
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                CrbsError::io_message(format!("spawn rpm2cpio for {}: {}", srpm.display(), e))
            })?;

        let mut cpio = tokio::process::Command::new("cpio")
            .args(["-id", "*.spec"])
            .current_dir(&dest_dir)
            .stdin(std::process::Stdio::piped())
            // cpio -id 的 "XXXX blocks" 进度刷屏，丢弃。
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| CrbsError::from_io_context("spawn cpio", e))?;

        let mut stdout = rpm2cpio
            .stdout
            .take()
            .ok_or_else(|| CrbsError::io_message("rpm2cpio stdout unavailable"))?;
        let mut stdin = cpio
            .stdin
            .take()
            .ok_or_else(|| CrbsError::io_message("cpio stdin unavailable"))?;

        if let Err(e) = tokio::io::copy(&mut stdout, &mut stdin).await {
            drop(stdin);
            return Err(CrbsError::from_io_context("pipe rpm2cpio -> cpio", e));
        }
        // 同 prescan：EOF 靠 drop 关 fd 送达（shutdown 是 no-op）。
        drop(stdin);

        let (rpm_status, cpio_status) = tokio::try_join!(rpm2cpio.wait(), cpio.wait())
            .map_err(|e| CrbsError::from_io_context("wait rpm2cpio/cpio", e))?;

        if !cpio_status.success() || !rpm_status.success() {
            return Err(CrbsError::io_message(format!(
                "extract spec from {} failed: rpm2cpio={:?}, cpio={:?}",
                srpm.display(),
                rpm_status.code(),
                cpio_status.code()
            )));
        }

        let mut entries = tokio::fs::read_dir(&dest_dir)
            .await
            .map_err(|e| CrbsError::from_io_context("read spec extract dir", e))?;

        let mut specs = Vec::new();
        // 迭代错误必须传播：吞掉会把 IO 错误伪装成 "no .spec found" 的输入
        // 问题，掩盖真实环境/磁盘故障。
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| CrbsError::from_io_context("iterate spec extract dir", e))?
        {
            let path = entry.path();
            if path.extension().map(|e| e == "spec").unwrap_or(false) {
                specs.push(path);
            }
        }
        // read_dir 顺序因文件系统而异；排序保证多个 .spec 时选择确定。
        specs.sort();
        if let Some(spec) = specs.first() {
            return Ok(spec.clone());
        }

        Err(CrbsError::ValidationFailed {
            message: format!("no .spec found in SRPM: {}", srpm.display()),
        })
    };

    match timeout {
        Some(d) => tokio::time::timeout(d, async {
            match cancel_token {
                Some(token) => tokio::select! {
                    r = run_fut => r,
                    _ = token.cancelled() => Err(CrbsError::Cancelled),
                },
                None => run_fut.await,
            }
        })
        .await
        .map_err(|_| CrbsError::Timeout)?,
        None => match cancel_token {
            Some(token) => tokio::select! {
                r = run_fut => r,
                _ = token.cancelled() => Err(CrbsError::Cancelled),
            },
            None => run_fut.await,
        },
    }
}

/// 收集目录下的 `.rpm` 文件路径：直接子项 + `RPMS`/`SRPMS` 子目录（兼容
/// mock 布局 `RPMS/<arch>/*.rpm` 多扫一层，SRPMS 仍一层）；recursive=true
/// 递归全子目录。与 artifact_harvest 一致：不跟随 symlink。
pub async fn collect_rpm_paths(dir: &Path, recursive: bool) -> std::io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    // (目录, 深度)。非递归模式下：0 = 扫描根，1 = RPMS/SRPMS，2 = arch 子目录。
    let mut dirs = vec![(dir.to_path_buf(), 0_u8)];

    while let Some((current, depth)) = dirs.pop() {
        let mut entries = tokio::fs::read_dir(&current).await?;
        while let Some(entry) = entries.next_entry().await? {
            let file_type = entry.file_type().await?;
            let path = entry.path();
            if file_type.is_file() && path.extension().and_then(|s| s.to_str()) == Some("rpm") {
                paths.push(path);
            } else if file_type.is_dir() {
                if recursive {
                    dirs.push((path, depth.saturating_add(1)));
                } else if depth == 0
                    && path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .map(|name| name == "RPMS" || name == "SRPMS")
                        .unwrap_or(false)
                {
                    dirs.push((path, 1));
                } else if depth == 1 {
                    dirs.push((path, 2));
                }
            }
        }
    }
    paths.sort();
    Ok(paths)
}

/// 进程存活探测（`kill(pid, 0)`：不投递信号，仅查存在性/权限），worker
/// 启动期回收本地陈旧构建行用。`pid <= 0` 不存活；`EPERM`（进程在但属
/// 他人）按存活——误回收（双执行）的代价远高于漏回收。
pub fn pid_alive(pid: i64) -> bool {
    if pid <= 0 {
        return false;
    }
    let rc = unsafe { nix::libc::kill(pid as nix::libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() != Some(nix::libc::ESRCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_rpm_name() {
        assert_eq!(extract_rpm_name("kernel-6.12.0-1.el9.src.rpm"), "kernel");
        assert_eq!(
            extract_rpm_name("kernel-rt-6.12.0-1.el9.src.rpm"),
            "kernel-rt"
        );
        assert_eq!(
            extract_rpm_name("gcc-toolset-14-14.0-1.el9.x86_64.rpm"),
            "gcc-toolset-14"
        );
        assert_eq!(
            extract_rpm_name("libstdc++-14.2.0-1.el9.x86_64.rpm"),
            "libstdc++"
        );
        assert_eq!(extract_rpm_name("tmux-3.5a-7.fc42.src.rpm"), "tmux");
        assert_eq!(extract_rpm_name("no-dash"), "no-dash");
    }

    #[test]
    fn test_shell_quote() {
        assert_eq!(shell_quote("hello"), "'hello'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("a'b'c"), "'a'\\''b'\\''c'");
    }

    /// 预植 symlink 的结果目录写：链接目标保持不变，链接本身被替换为普通文件。
    #[cfg(unix)]
    #[tokio::test]
    async fn write_result_file_no_follow_replaces_symlink_without_touching_target() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("host-secret");
        std::fs::write(&target, b"secret").unwrap();
        let path = tmp.path().join("crbs-build.sh");
        std::os::unix::fs::symlink(&target, &path).unwrap();

        write_result_file_no_follow(&path, b"script").await.unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"secret");
        assert_eq!(std::fs::read(&path).unwrap(), b"script");
        assert!(!std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    // cpio 成员名预扫（防 `..` 成员穿越写出解包目录）

    /// 拒绝 `..` 分量与绝对路径成员（消息含成员名）；`./` 前缀与普通相对路径放行。
    #[test]
    fn cpio_member_names_reject_traversal_and_absolute() {
        assert!(validate_cpio_member_names("pkg.spec\n./pkg.spec\nsub/dir/pkg.spec\n\n").is_ok());
        for evil in ["../evil.spec", "dir/../../evil.spec", "/etc/evil.spec"] {
            let err = validate_cpio_member_names(&format!("good.spec\n{evil}\n")).unwrap_err();
            assert!(
                matches!(&err, CrbsError::ValidationFailed { message }
                    if message.contains(evil)),
                "member {evil:?} must be rejected with its name, got: {err:?}"
            );
        }
    }

    /// 外部 cpio 是否可用（缺失时跳过依赖真实 cpio 的断言）。
    fn cpio_available() -> bool {
        std::process::Command::new("cpio")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// rpm2cpio 是否可 spawn（脚本对 `--version` 退出非零是预期，只看 spawn）。
    fn rpm2cpio_spawnable() -> bool {
        std::process::Command::new("rpm2cpio")
            .arg("--version")
            .output()
            .is_ok()
    }

    /// 真实 cpio 行为锁定（GNU/bsdcpio 双跑）：`cpio -o` 会把字面
    /// `../outer/evil.spec` 打进档案、`-it` 原样列出——预扫必须拒收。
    #[test]
    fn cpio_prescan_rejects_real_dotdot_archive() {
        if !cpio_available() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        // cpio -o 按名字归档、文件须真实存在；从 inner/ 引用 `../` 造穿越成员名。
        let outer = tmp.path().join("outer");
        std::fs::create_dir_all(&outer).unwrap();
        std::fs::write(outer.join("evil.spec"), b"evil").unwrap();
        let inner = tmp.path().join("inner");
        std::fs::create_dir_all(&inner).unwrap();

        let pack = |names: &str, cwd: &std::path::Path, out: &std::path::Path| {
            use std::io::Write;
            let mut child = std::process::Command::new("cpio")
                .arg("-o")
                .arg("-F")
                .arg(out)
                .current_dir(cwd)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn cpio -o");
            child
                .stdin
                .as_mut()
                .expect("cpio -o stdin")
                .write_all(names.as_bytes())
                .expect("feed cpio member names");
            child.wait_with_output().expect("wait cpio -o").status
        };

        // 恶意档案：成员 `../outer/evil.spec`。
        let evil_archive = tmp.path().join("evil.cpio");
        let st = pack("../outer/evil.spec\n", &inner, &evil_archive);
        assert!(st.success(), "cpio -o for evil fixture failed: {st}");

        let list = std::process::Command::new("cpio")
            .arg("-it")
            .stdin(std::process::Stdio::from(
                std::fs::File::open(&evil_archive).unwrap(),
            ))
            .output()
            .expect("spawn cpio -it");
        assert!(list.status.success(), "cpio -it failed: {list:?}");
        let listing = String::from_utf8_lossy(&list.stdout);
        assert!(
            listing.contains("../outer/evil.spec"),
            "fixture must contain the literal dot-dot member, got: {listing:?}"
        );
        let err = validate_cpio_member_names(&listing).unwrap_err();
        assert!(
            matches!(&err, CrbsError::ValidationFailed { message }
                if message.contains("../outer/evil.spec")),
            "real cpio listing with dot-dot member must be rejected, got: {err:?}"
        );

        // 合法档案：普通相对成员名 → 放行。
        std::fs::write(tmp.path().join("pkg.spec"), b"spec").unwrap();
        let ok_archive = tmp.path().join("ok.cpio");
        let st = pack("pkg.spec\n", tmp.path(), &ok_archive);
        assert!(st.success(), "cpio -o for legit fixture failed: {st}");
        let list = std::process::Command::new("cpio")
            .arg("-it")
            .stdin(std::process::Stdio::from(
                std::fs::File::open(&ok_archive).unwrap(),
            ))
            .output()
            .expect("spawn cpio -it");
        assert!(list.status.success(), "cpio -it failed: {list:?}");
        assert!(validate_cpio_member_names(&String::from_utf8_lossy(&list.stdout)).is_ok());
    }

    /// 真实 RPM 回归：fixture payload 成员 `./usr/share/...` 必须过预扫（勿因
    /// `./` 前缀误拒合法 RPM）；payload 无 `.spec`，走完预扫+解包后报
    /// "no .spec found" 即证合法链路未破。
    #[tokio::test]
    async fn extract_spec_prescan_passes_real_rpm_payload() {
        if !cpio_available() || !rpm2cpio_spawnable() {
            return;
        }
        let srpm = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rpms/crbs-test-fixture-1.0-1.noarch.rpm");
        let dest = tempfile::tempdir().unwrap();
        let err = extract_spec_from_srpm(&srpm, dest.path(), None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, CrbsError::ValidationFailed { message }
                if message.contains("no .spec")),
            "legit RPM must pass prescan and reach the no-spec error, got: {err:?}"
        );
    }

    /// 转义不变量：常见控制字符短转义、其余 C0/DEL 用 \xHH，输出整体
    /// 单行，普通字符（含反斜杠）原样保留。
    #[test]
    fn escape_ctrl_maps_common_and_remaining_control_chars() {
        assert_eq!(escape_ctrl("a\tb\rc\nd"), "a\\tb\\rc\\nd");
        assert_eq!(escape_ctrl("\x00\x01\x1f\x7f"), "\\x00\\x01\\x1f\\x7f");
        assert_eq!(escape_ctrl("plain \\ path é"), "plain \\ path é");
        assert_eq!(escape_ctrl(""), "");
        // 转义后不再含裸控制字符（不可借日志伪造新行）。
        assert!(!escape_ctrl("x\ny\rz").chars().any(|c| c.is_control()));
    }

    /// 节流语义：首败告警、此后每第 N 次连续失败告警、成功复位。
    #[test]
    fn warn_throttle_logs_first_then_every_nth_consecutive_failure() {
        let mut t = WarnThrottle::new(20);
        assert!(t.fail());
        for _ in 2..20 {
            assert!(!t.fail());
        }
        assert!(t.fail());
        t.reset();
        assert!(t.fail());
        assert!(!t.fail());
    }

    /// 饱和方向必须是 i64::MAX（保留期极长 ≈ 不清理），绝不能回绕成负数
    /// （"N 天前"变未来时刻 → retention GC 匹配所有行）。
    #[test]
    fn u64_to_i64_saturating_never_wraps_negative() {
        assert_eq!(u64_to_i64_saturating(0), 0);
        assert_eq!(u64_to_i64_saturating(42), 42);
        assert_eq!(u64_to_i64_saturating(i64::MAX as u64), i64::MAX);
        assert_eq!(u64_to_i64_saturating(i64::MAX as u64 + 1), i64::MAX);
        assert_eq!(u64_to_i64_saturating(u64::MAX), i64::MAX);
    }

    #[test]
    fn half_jitter_delay_stays_within_half_to_full_bounds() {
        let base = Duration::from_secs(1);
        for attempt in 1..=3 {
            let full = base * 2_u32.pow(attempt - 1);
            // half jitter：frac=0 取下界 full/2，frac=1 取上界 full。
            assert_eq!(half_jitter_delay(attempt, base, 0.0), full / 2);
            assert_eq!(half_jitter_delay(attempt, base, 1.0), full);
            let mid = half_jitter_delay(attempt, base, 0.5);
            assert!(mid >= full / 2 && mid <= full);
        }
    }

    #[test]
    fn half_jitter_delay_now_samples_vary() {
        // 随机源健康检查：8 个样本不应全等（RandomState 密钥来自 OS RNG）。
        let base = Duration::from_secs(1);
        let samples: Vec<Duration> = (0..8).map(|_| half_jitter_delay_now(1, base)).collect();
        assert!(samples.iter().any(|s| *s != samples[0]));
    }

    #[test]
    fn half_jitter_delay_edges() {
        let base = Duration::from_secs(1);
        // attempt 0 不下溢 panic，行为与 attempt 1 一致。
        assert_eq!(
            half_jitter_delay(0, base, 0.0),
            half_jitter_delay(1, base, 0.0)
        );
        // 巨大 attempt 饱和在 2^31 指数上，不 panic。
        assert_eq!(
            half_jitter_delay(40, base, 0.5),
            half_jitter_delay(32, base, 0.5)
        );
    }

    #[test]
    fn test_srpm_display_name() {
        use std::path::Path;
        assert_eq!(
            srpm_display_name(Path::new("/home/user/git-lfs-3.7.1-4.fc44.src.rpm")),
            "git-lfs-3.7.1-4.fc44"
        );
        assert_eq!(
            srpm_display_name(Path::new("/tmp/gpgverify-2.2-4.fc44.src.rpm")),
            "gpgverify-2.2-4.fc44"
        );
        assert_eq!(
            srpm_display_name(Path::new("no-1.0-1.fc44.src.rpm")),
            "no-1.0-1.fc44"
        );
        assert_eq!(srpm_display_name(Path::new("foo.txt")), "unknown");
    }

    #[test]
    fn test_split_nvr() {
        assert_eq!(
            split_nvr("httpd-2.4.51-34.oe2203sp4"),
            ("httpd", "2.4.51", "34.oe2203sp4")
        );
        assert_eq!(
            split_nvr("git-lfs-3.7.1-4.fc44"),
            ("git-lfs", "3.7.1", "4.fc44")
        );
        assert_eq!(split_nvr("no-1.0-1.fc44"), ("no", "1.0", "1.fc44"));
        assert_eq!(split_nvr("foo"), ("foo", "", ""));
        assert_eq!(split_nvr("bar-1.0"), ("bar-1.0", "", ""));
    }

    /// 存储帧只认空格分隔：T/RFC3339/纯日期/空一律 None（透传降级的依据）。
    #[test]
    fn parse_db_time_locks_storage_frame() {
        assert_eq!(
            parse_db_time("2026-08-30 12:34:56").map(|n| n.and_utc().to_rfc3339()),
            Some("2026-08-30T12:34:56+00:00".to_string())
        );
        assert_eq!(parse_db_time("2026-08-30T12:34:56"), None);
        assert_eq!(parse_db_time("2026-08-30T12:34:56Z"), None);
        assert_eq!(parse_db_time("2026-08-30 12:34:56+08:00"), None);
        assert_eq!(parse_db_time("2026-08-30"), None);
        assert_eq!(parse_db_time(""), None);
        assert_eq!(parse_db_time("not a time"), None);
    }

    /// 生成侧与解析侧互锁：`db_now_utc` 的输出必须落在 `parse_db_time`
    /// 认的帧内（任一侧格式漂移即失败），另以固定分隔位钉住 19 字节形状。
    #[test]
    fn db_now_utc_roundtrips_storage_frame() {
        let s = db_now_utc();
        assert_eq!(s.len(), 19, "{s}");
        for (i, b) in s.bytes().enumerate() {
            let expect = match i {
                4 | 7 => b'-',
                10 => b' ',
                13 | 16 => b':',
                _ => {
                    assert!(b.is_ascii_digit(), "non-digit at {i}: {s}");
                    continue;
                }
            };
            assert_eq!(b, expect, "separator at {i}: {s}");
        }
        let naive = parse_db_time(&s).expect("db_now_utc must be parseable");
        // 值就是当前 UTC（±2s 容忍测试执行耗时）。
        assert!((Utc::now() - naive.and_utc()).num_seconds().abs() <= 2);
    }

    /// `format_local_now` 与本地墙钟一致（±2s 容忍耗时）：秒级截断、无
    /// %Z/亚秒，形状同存储帧但语义是本地时区。
    #[test]
    fn format_local_now_tracks_local_wall_clock() {
        use chrono::TimeZone as _;

        let s = format_local_now();
        assert_eq!(s.len(), 19, "{s}");
        let naive =
            NaiveDateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S").expect("locked 19-byte shape");
        let now_local = Local::now();
        let produced = Local
            .from_local_datetime(&naive)
            .single()
            .expect("single local offset");
        assert!(
            now_local
                .signed_duration_since(produced)
                .num_seconds()
                .abs()
                <= 2,
            "local={now_local}, produced={produced}"
        );
    }

    /// 完整显示路径：UTC 墙钟 → 本地时区 + `%Z` 后缀（期望值在测试侧用独立
    /// 字面量构造，钉住格式串）；占位与不可解析输入按约定降级。
    #[test]
    fn format_local_time_formats_and_degrades() {
        let expected = NaiveDateTime::parse_from_str("2026-08-30 04:05:06", "%Y-%m-%d %H:%M:%S")
            .expect("fixed")
            .and_utc()
            .with_timezone(&Local)
            .format("%Y-%m-%d %H:%M:%S %Z")
            .to_string();
        assert_eq!(format_local_time("2026-08-30 04:05:06"), expected);
        assert_eq!(format_local_time("-"), "-");
        assert_eq!(format_local_time(""), "-");
        assert_eq!(
            format_local_time("2026-08-30T04:05:06Z"),
            "2026-08-30T04:05:06Z"
        );
    }

    #[test]
    fn test_validate_pkg_name_accepts_valid_names() {
        assert!(validate_pkg_name("kernel").is_ok());
        assert!(validate_pkg_name("kernel-rt").is_ok());
        assert!(validate_pkg_name("gcc-toolset-14").is_ok());
        assert!(validate_pkg_name("libstdc++").is_ok());
    }

    #[test]
    fn test_validate_pkg_name_rejects_traversal_and_separators() {
        assert!(validate_pkg_name("..").is_err());
        assert!(validate_pkg_name("../etc").is_err());
        assert!(validate_pkg_name("foo/..").is_err());
        assert!(validate_pkg_name("foo/bar").is_err());
        assert!(validate_pkg_name("foo\0bar").is_err());
        assert!(validate_pkg_name("").is_err());
    }

    #[test]
    fn test_validate_path_no_traversal() {
        use std::path::Path;

        assert!(validate_path_no_traversal(Path::new("/var/lib/crbs"), true).is_ok());
        assert!(validate_path_no_traversal(Path::new("/var/lib/crbs"), false).is_ok());
        assert!(validate_path_no_traversal(Path::new("var/lib/crbs"), false).is_ok());

        assert!(validate_path_no_traversal(Path::new("/var/../etc"), true).is_err());
        assert!(validate_path_no_traversal(Path::new("/var/../etc"), false).is_err());
        assert!(validate_path_no_traversal(Path::new("../etc"), false).is_err());
        assert!(validate_path_no_traversal(Path::new("/etc\0shadow"), true).is_err());

        assert!(validate_path_no_traversal(Path::new("relative/path"), true).is_err());
        assert!(validate_path_no_traversal(Path::new("relative/path"), false).is_ok());
    }

    #[test]
    fn test_validate_srpm_path() {
        use std::path::Path;

        assert!(validate_srpm_path(Path::new("/tmp/pkg-1.0-1.fc44.src.rpm")).is_ok());

        assert!(validate_srpm_path(Path::new("pkg-1.0-1.fc44.src.rpm")).is_err());
        assert!(validate_srpm_path(Path::new("/tmp/pkg-1.0-1.fc44.rpm")).is_err());
        assert!(validate_srpm_path(Path::new("/tmp/../etc/pkg-1.0-1.fc44.src.rpm")).is_err());
        assert!(validate_srpm_path(Path::new("/tmp/pkg\0-1.0.src.rpm")).is_err());
    }

    #[tokio::test]
    async fn collect_rpm_paths_mock_layout_non_recursive() {
        let tmp = tempfile::tempdir().unwrap();
        let rpms = tmp.path().join("RPMS");
        let srpms = tmp.path().join("SRPMS");
        tokio::fs::create_dir_all(rpms.join("x86_64"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(&srpms).await.unwrap();
        tokio::fs::write(rpms.join("x86_64/a.rpm"), b"rpm")
            .await
            .unwrap();
        tokio::fs::write(srpms.join("b.src.rpm"), b"rpm")
            .await
            .unwrap();

        let paths = collect_rpm_paths(tmp.path(), false).await.unwrap();
        assert_eq!(
            paths,
            vec![rpms.join("x86_64/a.rpm"), srpms.join("b.src.rpm")]
        );
    }

    #[tokio::test]
    async fn collect_rpm_paths_skips_symlinked_rpm() {
        let tmp = tempfile::tempdir().unwrap();
        let arch = tmp.path().join("RPMS/x86_64");
        tokio::fs::create_dir_all(&arch).await.unwrap();
        tokio::fs::write(arch.join("real.rpm"), b"rpm")
            .await
            .unwrap();
        let outside_dir = tempfile::tempdir().unwrap();
        let outside = outside_dir.path().join("outside.rpm");
        tokio::fs::write(&outside, b"rpm").await.unwrap();
        std::os::unix::fs::symlink(&outside, arch.join("link.rpm")).unwrap();

        let paths = collect_rpm_paths(tmp.path(), false).await.unwrap();
        assert_eq!(paths, vec![arch.join("real.rpm")]);
    }

    #[tokio::test]
    async fn collect_rpm_paths_recursive_nested() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("a/b");
        tokio::fs::create_dir_all(&nested).await.unwrap();
        tokio::fs::write(nested.join("c.rpm"), b"rpm")
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("top.rpm"), b"rpm")
            .await
            .unwrap();

        let paths = collect_rpm_paths(tmp.path(), true).await.unwrap();
        assert_eq!(
            paths,
            vec![nested.join("c.rpm"), tmp.path().join("top.rpm")]
        );
    }

    #[tokio::test]
    async fn canonicalize_within_rejects_symlink_escape_for_missing_path() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let link = root.path().join("out");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();

        // out/x.rpm 尚不存在：纯词法 starts_with 会放行，必须经 canonicalize 祖先拦截
        let target = link.join("x.rpm");
        assert!(canonicalize_within(&target, root.path()).await.is_err());
    }

    #[tokio::test]
    async fn canonicalize_within_accepts_missing_path_under_root() {
        let root = tempfile::tempdir().unwrap();
        tokio::fs::create_dir(root.path().join("sub"))
            .await
            .unwrap();
        let canon_root = std::fs::canonicalize(root.path()).unwrap();

        // sub/deeper/x.rpm 中 deeper/x.rpm 均不存在，最深已存在祖先是 sub
        let p = canonicalize_within(&root.path().join("sub/deeper/x.rpm"), root.path())
            .await
            .unwrap();
        assert_eq!(p, canon_root.join("sub/deeper/x.rpm"));
    }

    #[tokio::test]
    async fn canonicalize_within_rejects_parent_dir_suffix() {
        let root = tempfile::tempdir().unwrap();
        let escape = root.path().join("sub/../../escape.rpm");
        assert!(canonicalize_within(&escape, root.path()).await.is_err());
    }
}
