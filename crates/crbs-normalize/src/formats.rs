// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 载荷格式识别与时间字段就地归一化：magic 因子（ar 成员头、zip 中央目录+
//! 本地头、gzip 头 mtime）与路径因子（R DESCRIPTION Built 行、R Meta/
//! package.rds 内容、javadoc 生成 HTML 内嵌时间）双通道。任一解析失败由调
//! 用方整文件放弃（原样保留），函数只做内存改写、不落盘。

use std::ffi::OsStr;
use std::path::Path;

use crate::rds;
use crate::text;

use crate::dos::epoch_to_dos;

/// ar 全局头（member 头前 8 字节）。
const AR_MAGIC: &[u8] = b"!<arch>\n";
/// ar 成员头固定 60 字节。
const AR_HEADER_LEN: usize = 60;
/// ar uid/gid 字段（各 6 字节）的确定化取值：0 左对齐空格填充。
const AR_ID_ZERO: &[u8; 6] = b"0     ";

/// zip 本地文件头签名（必须在 offset 0 才认作 zip）。
const ZIP_LOCAL_MAGIC: &[u8] = b"PK\x03\x04";
/// zip 中央目录头签名。
const ZIP_CENTRAL_MAGIC: &[u8] = b"PK\x01\x02";
/// zip EOCD 签名。
const ZIP_EOCD_MAGIC: &[u8] = b"PK\x05\x06";
/// EOCD 向前扫描窗口：最大注释 64KB + 固定 22 字节。
const ZIP_EOCD_SCAN: usize = 22 + 65_535;
/// zip 中央目录头固定字段长度。
const ZIP_CENTRAL_HDR: usize = 46;
/// zip EOCD 固定字段长度。
const ZIP_EOCD_HDR: usize = 22;

/// gzip 魔数（0x1f 0x8b）。
const GZIP_MAGIC: &[u8] = &[0x1f, 0x8b];

/// 路径键控 handler 的单文件扫描上限：三个目标（DESCRIPTION ~KB、
/// package.rds ~KB、javadoc HTML ≤ 数百 KB）均远小于此，防误扫大文件。
const MAX_PATH_KEYED_SCAN: usize = 4 * 1024 * 1024;

/// 可归一化的载荷格式：magic 三类 + 路径键控三类，识别即定 handler。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    Ar,
    Zip,
    Gzip,
    /// R 包 DESCRIPTION 的 Built 行（精确文件名键控）。
    RDescription,
    /// R 包 Meta/package.rds 的 gzip 容器内容（精确文件名+父目录键控）。
    RPkgRds,
    /// javadoc 生成 HTML 的生成注释（.html 扩展名键控，大小写不敏感）。
    JavadocHtml,
}

impl Format {
    /// 双因子识别：先路径键控（精确文件名/扩展名 + 内容门禁），再 magic。
    /// 路径键控优先——package.rds 同时命中 gzip magic，须走内容级 handler
    /// 而非仅清洗 gzip 头。门禁不满足即回落/放弃（不认识就跳过）。
    pub(crate) fn detect(data: &[u8], rel_path: &Path) -> Option<Format> {
        Self::detect_by_path(data, rel_path).or_else(|| Self::detect_by_magic(data))
    }

    /// 路径键控通道：文件名/扩展名 + 廉价内容门禁（DESCRIPTION 验 UTF-8、
    /// javadoc 验字节级 ASCII 窗口），严格解析留给 normalize。
    fn detect_by_path(data: &[u8], rel_path: &Path) -> Option<Format> {
        if data.len() > MAX_PATH_KEYED_SCAN {
            return None;
        }
        let name = rel_path.file_name()?;
        if name == OsStr::new("DESCRIPTION") {
            // R 包描述文件：非 UTF-8 或无 Built 行的任意同名文件静默跳过
            let text = std::str::from_utf8(data).ok()?;
            return text.contains("Built: R ").then_some(Format::RDescription);
        }
        if name == OsStr::new("package.rds")
            && rel_path.parent().and_then(Path::file_name) == Some(OsStr::new("Meta"))
            && is_gzip_deflate(data)
        {
            return Some(Format::RPkgRds);
        }
        let is_html = rel_path
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|e| e.eq_ignore_ascii_case("html"));
        if is_html {
            // javadoc 门禁字节级验证（text::javadoc_gate）：非 UTF-8 文件只要
            // 注释窗口纯 ASCII 即认领，正文高字节不构成放弃理由
            return text::javadoc_gate(data).then_some(Format::JavadocHtml);
        }
        None
    }

    /// 按文件头 magic 识别格式；ar 优先（前 8 字节全等），zip 要求
    /// `PK\x03\x04` 恰在 offset 0，gzip 要求前 2 字节 1f 8b 且第 3 字节
    /// CM=8（deflate）——防非 gzip 文件恰以 1f 8b 开头被误识别后覆写载荷。
    fn detect_by_magic(data: &[u8]) -> Option<Format> {
        if data.starts_with(AR_MAGIC) {
            Some(Format::Ar)
        } else if data.starts_with(ZIP_LOCAL_MAGIC) {
            Some(Format::Zip)
        } else if is_gzip_deflate(data) {
            Some(Format::Gzip)
        } else {
            None
        }
    }

    /// 就地归一化 `data` 内嵌时间戳到 `epoch`；路径键控的文本/容器 handler
    /// 允许改变尺寸（变长段摘除、stored 重编码），Ok(是否有字节被改写) =
    /// 全量解析成功，Err = 格式解析失败，调用方须放弃整个文件不得写回。
    pub(crate) fn normalize(self, data: &mut Vec<u8>, epoch: i64) -> Result<bool, String> {
        match self {
            Format::Ar => normalize_ar(data, epoch),
            Format::Zip => normalize_zip(data, epoch),
            Format::Gzip => normalize_gzip(data, epoch),
            Format::RDescription => text::normalize_r_description(data, epoch),
            Format::RPkgRds => rds::normalize_pkg_rds(data, epoch),
            Format::JavadocHtml => text::normalize_javadoc_html(data, epoch),
        }
    }
}

/// gzip 头判定：前 2 字节 1f 8b 且第 3 字节 CM=8（deflate）。
fn is_gzip_deflate(data: &[u8]) -> bool {
    data.starts_with(GZIP_MAGIC) && data.get(2) == Some(&8)
}

/// gzip mtime 字段（LE u32）取值：epoch 超出 u32 表示域写 0，与 gzip 对该
/// 字段"无时间戳"的语义一致；gzip 头 handler 与 package.rds 重编码共用。
pub(crate) fn gzip_mtime_u32(epoch: i64) -> u32 {
    if (0..=i64::from(u32::MAX)).contains(&epoch) {
        epoch as u32
    } else {
        0
    }
}

/// 定长 ASCII 字段截取（去尾部空格）；非 UTF-8 即格式损坏。
fn ascii_field(data: &[u8], range: std::ops::Range<usize>) -> Result<&str, String> {
    let raw = data
        .get(range.clone())
        .ok_or_else(|| format!("field {range:?} out of bounds"))?;
    let text = std::str::from_utf8(raw).map_err(|_| format!("field {range:?} not ASCII"))?;
    Ok(text.trim_end_matches(' '))
}

/// 读 LE u16（越界 = 格式损坏）。
fn le_u16(data: &[u8], off: usize) -> Result<u16, String> {
    let hi = off
        .checked_add(2)
        .ok_or_else(|| format!("offset {off} overflow"))?;
    let pair = data
        .get(off..hi)
        .ok_or_else(|| format!("u16 at {off} out of bounds"))?;
    Ok(u16::from_le_bytes([pair[0], pair[1]]))
}

/// 读 LE u32（越界 = 格式损坏）。
fn le_u32(data: &[u8], off: usize) -> Result<u32, String> {
    let hi = off
        .checked_add(4)
        .ok_or_else(|| format!("offset {off} overflow"))?;
    let quad = data
        .get(off..hi)
        .ok_or_else(|| format!("u32 at {off} out of bounds"))?;
    Ok(u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]]))
}

/// 写字节切片（越界 = 格式损坏）；写入前比对，无差异不落笔，返回是否有
/// 差异（调用方累计为 changed 标记，未变不写回文件）。
fn write_bytes(data: &mut [u8], off: usize, bytes: &[u8]) -> Result<bool, String> {
    let hi = off
        .checked_add(bytes.len())
        .ok_or_else(|| format!("offset {off} overflow"))?;
    let slot = data
        .get_mut(off..hi)
        .ok_or_else(|| format!("write at {off} out of bounds"))?;
    if slot == bytes {
        return Ok(false);
    }
    slot.copy_from_slice(bytes);
    Ok(true)
}

/// ar 归一化：逐成员走 60 字节头，mtime（16..28）就地改写为 epoch 十进制
/// 左对齐空格填充（GNU ar `%-12ld` 口径），uid（28..34）/gid（34..40）就地
/// 写固定 0——binutils deterministic 口径，同配方双侧同值即确定；只改
/// mtime 不够，strip 重写 .a 时会把执行者凭据写进 uid/gid（随构建环境漂
/// 移）。`//`（长名表）与 `/`（符号索引）成员头同构，随统一循环一并改写。
/// 成员数据按 2 字节对齐跳过；end magic（`\x60\x0a`）不符或 size 不可解析
/// 即整体失败。
fn normalize_ar(data: &mut [u8], epoch: i64) -> Result<bool, String> {
    let mut field = [b' '; 12];
    let text = epoch.to_string();
    // 12 字节字段容量；SDE 锚为 10 位量级，极端 i64（20 位）无法承载即放弃
    if text.len() > field.len() {
        return Err(format!("epoch {epoch} exceeds ar mtime field width"));
    }
    field[..text.len()].copy_from_slice(text.as_bytes());

    let mut changed = false;
    let mut off = AR_MAGIC.len();
    while off < data.len() {
        let hdr_end = off
            .checked_add(AR_HEADER_LEN)
            .ok_or_else(|| format!("ar header offset {off} overflow"))?;
        if hdr_end > data.len() {
            return Err(format!("truncated ar member header at {off}"));
        }
        if &data[off + 58..off + 60] != b"`\n" {
            return Err(format!("bad ar member magic at {off}"));
        }
        let size: usize = ascii_field(data, off + 48..off + 58)?
            .parse()
            .map_err(|_| format!("unparseable ar member size at {off}"))?;
        changed |= write_bytes(data, off + 16, &field)?;
        changed |= write_bytes(data, off + 28, AR_ID_ZERO)?;
        changed |= write_bytes(data, off + 34, AR_ID_ZERO)?;
        let data_end = hdr_end
            .checked_add(size)
            .ok_or_else(|| format!("ar member size {size} overflow"))?;
        if data_end > data.len() {
            return Err(format!("ar member data truncated at {off}"));
        }
        // 奇数长度成员补 1 字节对齐填充；末成员缺填充时越界即自然终止
        off = data_end.saturating_add(size & 1);
    }
    Ok(changed)
}

/// zip 归一化：从文件尾向前扫 EOCD（64KB+22 窗口），一致性校验通过后逐
/// 中央目录项改写 dos time/date（12..16），并按本地头偏移回改本地头
/// time/date（10..14，先验签名）。zip64、偏移不自洽、注释长度不符均视为
/// 解析失败整体放弃（沙箱场景宁可不归一化不可改坏）。上限：extra 字段
///（UT 0x5455 / NTFS 0x000a）内嵌 unix 时间不清洗，Info-ZIP 产物仍带时间
/// 差，JDK jar（无 extra 时间）已覆盖。
fn normalize_zip(data: &mut [u8], epoch: i64) -> Result<bool, String> {
    let (dos_date, dos_time) = epoch_to_dos(epoch);
    let date_bytes = dos_date.to_le_bytes();
    let time_bytes = dos_time.to_le_bytes();

    let scan_floor = data.len().saturating_sub(ZIP_EOCD_SCAN);
    let mut eocd = None;
    let mut probe = data
        .len()
        .checked_sub(ZIP_EOCD_HDR)
        .ok_or("file shorter than zip EOCD")?;
    loop {
        if data.get(probe..probe + 4) == Some(ZIP_EOCD_MAGIC)
            // 候选校验：注释长度必须恰好补齐到文件尾（排除注释内伪签名）
            && le_u16(data, probe + 20)? as usize + probe + ZIP_EOCD_HDR == data.len()
        {
            eocd = Some(probe);
            break;
        }
        if probe == scan_floor {
            break;
        }
        probe -= 1;
    }
    let eocd = eocd.ok_or("zip EOCD not found")?;

    let total_entries = le_u16(data, eocd + 10)? as usize;
    let cd_size = le_u32(data, eocd + 12)? as usize;
    let cd_offset = le_u32(data, eocd + 16)? as usize;
    // 中央目录必须恰好终止于 EOCD；0xFFFFFFFF 等 zip64 哨兵值在此自然失败
    if cd_offset.checked_add(cd_size) != Some(eocd) {
        return Err(format!(
            "zip central directory [{cd_offset}, +{cd_size}) does not end at EOCD {eocd}"
        ));
    }

    let mut changed = false;
    let mut off = cd_offset;
    for index in 0..total_entries {
        if data.get(off..off + 4) != Some(ZIP_CENTRAL_MAGIC) {
            return Err(format!("bad zip central header at {off} (entry {index})"));
        }
        changed |= write_bytes(data, off + 12, &time_bytes)?;
        changed |= write_bytes(data, off + 14, &date_bytes)?;
        let name_len = le_u16(data, off + 28)? as usize;
        let extra_len = le_u16(data, off + 30)? as usize;
        let comment_len = le_u16(data, off + 32)? as usize;
        let local_off = le_u32(data, off + 42)? as usize;
        off = off
            .checked_add(ZIP_CENTRAL_HDR + name_len + extra_len + comment_len)
            .ok_or_else(|| format!("zip central entry {index} offset overflow"))?;

        // 本地头回改：偏移来自中央目录，签名与固定段完整性不符即放弃
        if data.get(local_off..local_off + 4) != Some(ZIP_LOCAL_MAGIC) {
            return Err(format!(
                "bad zip local header at {local_off} (entry {index})"
            ));
        }
        changed |= write_bytes(data, local_off + 10, &time_bytes)?;
        changed |= write_bytes(data, local_off + 12, &date_bytes)?;
    }
    // 条目数必须恰好走完中央目录：total_entries==0 而 cd 非空（或条目长度
    // 与 cd_size 不符）在此暴露，不得静默漏归一化
    if off != eocd {
        return Err(format!(
            "zip central directory {total_entries} entries do not span [{cd_offset}, {eocd})"
        ));
    }
    Ok(changed)
}

/// gzip 归一化：头 4..8 的 LE u32 mtime 恒定在该位置（与 FLG/FEXTRA 等
/// 后续字段无关）。epoch 超出 u32 表示域（负值或 > u32::MAX）写 0，与
/// gzip 对该字段的"无时间戳"语义一致。上限：多成员（拼接）gzip 仅归一
/// 首成员，后续成员头的 mtime 不触碰。
fn normalize_gzip(data: &mut [u8], epoch: i64) -> Result<bool, String> {
    if data.len() < 8 {
        return Err(format!("gzip header truncated at {} bytes", data.len()));
    }
    let bytes = gzip_mtime_u32(epoch).to_le_bytes();
    if data[4..8] == bytes {
        return Ok(false);
    }
    data[4..8].copy_from_slice(&bytes);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 手拼 ar 夹具：全局头 + 一个 5 字节成员（奇数长度带 1 字节填充）。
    /// mtime/uid/gid 字段预填垃圾值（uid/gid 模拟 strip 写入的执行者凭据）。
    fn ar_fixture(mtime_text: &[u8; 12]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(AR_MAGIC);
        v.extend_from_slice(b"member.txt/     "); // name[16]
        v.extend_from_slice(mtime_text); // mtime[12]
        v.extend_from_slice(b"987   "); // uid[6]
        v.extend_from_slice(b"989   "); // gid[6]
        v.extend_from_slice(b"100644  "); // mode[8]
        v.extend_from_slice(b"5         "); // size[10]
        v.extend_from_slice(b"`\n"); // end[2]
        v.extend_from_slice(b"hello"); // 数据
        v.push(b'\n'); // 奇数对齐填充
        v
    }

    /// ar：mtime/uid/gid 三个字段同轮改写为锚值与固定 0，mode/size/数据与
    /// 填充原样。
    #[test]
    fn ar_rewrites_member_mtime_in_place() {
        let mut data = ar_fixture(b"1700000000  ");
        Format::Ar.normalize(&mut data, 1_791_458_952).unwrap();
        assert_eq!(&data[8 + 16..8 + 28], b"1791458952  ");
        assert_eq!(&data[8 + 28..8 + 34], b"0     ");
        assert_eq!(&data[8 + 34..8 + 40], b"0     ");
        assert_eq!(&data[8 + 40..8 + 48], b"100644  ");
        assert_eq!(&data[8 + 60..8 + 65], b"hello");
        assert_eq!(&data[8 + 65..8 + 66], b"\n");
    }

    /// ar 幂等：同锚重写同值，首次有改写、重放 changed=false 且字节零变化。
    #[test]
    fn ar_is_idempotent() {
        let mut data = ar_fixture(b"1700000000  ");
        assert!(Format::Ar.normalize(&mut data, 1_791_458_952).unwrap());
        let once = data.clone();
        assert!(!Format::Ar.normalize(&mut data, 1_791_458_952).unwrap());
        assert_eq!(data, once);
    }

    /// ar：`//` 长名表与 `/` 符号索引成员同构处理（mtime/uid/gid 一并改写），
    /// 符号索引的二进制数据按 size 跳过不影响后续成员。
    #[test]
    fn ar_rewrites_long_name_and_symbol_index_members() {
        let mut v = Vec::new();
        v.extend_from_slice(AR_MAGIC);
        // `//` 长名表成员：size 8（偶数无填充），数据是名字偏移表
        v.extend_from_slice(b"//              ");
        v.extend_from_slice(b"1111111111  ");
        v.extend_from_slice(b"987   ");
        v.extend_from_slice(b"989   ");
        v.extend_from_slice(b"0       ");
        v.extend_from_slice(b"8         ");
        v.extend_from_slice(b"`\n");
        v.extend_from_slice(b"nameidx/");
        // `/` 符号索引成员：数据含 `\x60\x0a` 字节也不受成员扫描影响
        v.extend_from_slice(b"/               ");
        v.extend_from_slice(b"2222222222  ");
        v.extend_from_slice(b"987   ");
        v.extend_from_slice(b"989   ");
        v.extend_from_slice(b"0       ");
        v.extend_from_slice(b"4         ");
        v.extend_from_slice(b"`\n");
        v.extend_from_slice(b"\x60\x0a\x00\x00");
        Format::Ar.normalize(&mut v, 1_791_458_952).unwrap();
        assert_eq!(&v[8 + 16..8 + 28], b"1791458952  ");
        assert_eq!(&v[8 + 28..8 + 34], b"0     ");
        assert_eq!(&v[8 + 34..8 + 40], b"0     ");
        let second = 8 + 60 + 8;
        assert_eq!(&v[second + 16..second + 28], b"1791458952  ");
        assert_eq!(&v[second + 28..second + 34], b"0     ");
        assert_eq!(&v[second + 34..second + 40], b"0     ");
    }

    /// ar：end magic 不符 → 整体失败；size 非数字 → 整体失败；截断头 → 失败。
    #[test]
    fn ar_rejects_malformed_members() {
        let mut bad_magic = ar_fixture(b"1700000000  ");
        bad_magic[8 + 58] = b'X';
        assert!(Format::Ar.normalize(&mut bad_magic, 1).is_err());

        let mut bad_size = ar_fixture(b"1700000000  ");
        bad_size[8 + 48..8 + 58].copy_from_slice(b"abcdefghij");
        assert!(Format::Ar.normalize(&mut bad_size, 1).is_err());

        let mut truncated = ar_fixture(b"1700000000  ");
        truncated.truncate(8 + 30);
        assert!(Format::Ar.normalize(&mut truncated, 1).is_err());
    }

    /// ar：epoch 超出 12 字节字段容量（i64 极值 20 位）→ 放弃不写。
    #[test]
    fn ar_rejects_epoch_wider_than_field() {
        let mut data = ar_fixture(b"1700000000  ");
        assert!(Format::Ar.normalize(&mut data, i64::MIN).is_err());
    }

    /// 手拼 zip 夹具：单条目（本地头 + 数据 + 中央目录 + EOCD），
    /// time/date 字段预填非零垃圾值。
    fn zip_fixture() -> Vec<u8> {
        let name = b"f.txt";
        let mut v = Vec::new();
        // 本地头：30 字节固定段，time/date 在 10..14
        v.extend_from_slice(ZIP_LOCAL_MAGIC);
        v.extend_from_slice(&[0u8; 6]); // version/flags/method
        v.extend_from_slice(&0x1111_u16.to_le_bytes()); // time
        v.extend_from_slice(&0x2222_u16.to_le_bytes()); // date
        v.extend_from_slice(&[0u8; 12]); // crc/sizes
        v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        v.extend_from_slice(&0_u16.to_le_bytes()); // extra
        v.extend_from_slice(name);
        v.extend_from_slice(b"body");
        // 中央目录头：46 字节固定段，time/date 在 12..16，本地头偏移在 42..46
        let cd_offset = v.len() as u32;
        v.extend_from_slice(ZIP_CENTRAL_MAGIC);
        v.extend_from_slice(&[0u8; 8]); // versions/flags/method
        v.extend_from_slice(&0x3333_u16.to_le_bytes()); // time
        v.extend_from_slice(&0x4444_u16.to_le_bytes()); // date
        v.extend_from_slice(&[0u8; 12]); // crc/sizes
        v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        v.extend_from_slice(&0_u16.to_le_bytes()); // extra
        v.extend_from_slice(&0_u16.to_le_bytes()); // comment
        v.extend_from_slice(&0_u16.to_le_bytes()); // disk
        v.extend_from_slice(&0_u16.to_le_bytes()); // internal attrs
        v.extend_from_slice(&0_u32.to_le_bytes()); // external attrs
        v.extend_from_slice(&0_u32.to_le_bytes()); // 本地头偏移 = 0（文件起点）
        v.extend_from_slice(name);
        let cd_size = v.len() - cd_offset as usize;
        // EOCD
        v.extend_from_slice(ZIP_EOCD_MAGIC);
        v.extend_from_slice(&0_u16.to_le_bytes()); // disk
        v.extend_from_slice(&0_u16.to_le_bytes()); // cd disk
        v.extend_from_slice(&1_u16.to_le_bytes()); // 本盘条目
        v.extend_from_slice(&1_u16.to_le_bytes()); // 总条目
        v.extend_from_slice(&(cd_size as u32).to_le_bytes());
        v.extend_from_slice(&cd_offset.to_le_bytes());
        v.extend_from_slice(&0_u16.to_le_bytes()); // comment len
        v
    }

    /// zip：中央目录与本地头的 time/date 同步改写为 epoch 的 DOS 对，
    /// 名字与数据原样。
    #[test]
    fn zip_rewrites_central_and_local_time_fields() {
        let mut data = zip_fixture();
        Format::Zip.normalize(&mut data, 1_791_458_952).unwrap();
        let (dos_date, dos_time) = (23_880_u16, 23_462_u16);
        assert_eq!(&data[10..12], &dos_time.to_le_bytes());
        assert_eq!(&data[12..14], &dos_date.to_le_bytes());
        let cd = 30 + 5 + 4; // 本地头 + 名字 + 数据
        assert_eq!(&data[cd + 12..cd + 14], &dos_time.to_le_bytes());
        assert_eq!(&data[cd + 14..cd + 16], &dos_date.to_le_bytes());
        assert_eq!(&data[30..35], b"f.txt");
    }

    /// zip 幂等：同锚重写同值，首次有改写、重放 changed=false 且字节零变化。
    #[test]
    fn zip_is_idempotent() {
        let mut data = zip_fixture();
        assert!(Format::Zip.normalize(&mut data, 1_791_458_952).unwrap());
        let once = data.clone();
        assert!(!Format::Zip.normalize(&mut data, 1_791_458_952).unwrap());
        assert_eq!(data, once);
    }

    /// zip：total_entries==0 但中央目录非空 → 条目数与目录尺寸不自洽，放弃
    /// （零迭代静默漏归一化封死）。
    #[test]
    fn zip_abandons_entry_count_short_of_directory() {
        let mut data = zip_fixture();
        let eocd = data.len() - 22;
        // 本盘条目 + 总条目两个 u16 清零，cd_size/cd_offset 保持非零自洽
        data[eocd + 8..eocd + 12].copy_from_slice(&0_u32.to_le_bytes());
        assert!(Format::Zip.normalize(&mut data, 1_791_458_952).is_err());
    }

    /// zip：EOCD 缺失、中央目录偏移不自洽、本地头签名损坏均整体失败。
    #[test]
    fn zip_rejects_malformed_structures() {
        let mut no_eocd = zip_fixture();
        no_eocd.truncate(no_eocd.len() - 22);
        assert!(Format::Zip.normalize(&mut no_eocd, 1).is_err());

        let mut bad_cd = zip_fixture();
        let eocd = bad_cd.len() - 22;
        // 破坏中央目录偏移（写 0xFFFFFFFF 哨兵，模拟 zip64/损坏）
        bad_cd[eocd + 16..eocd + 20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Format::Zip.normalize(&mut bad_cd, 1).is_err());

        let mut bad_local = zip_fixture();
        bad_local[0] = b'X';
        assert!(Format::Zip.normalize(&mut bad_local, 1).is_err());
    }

    /// zip：EOCD 之后出现尾部垃圾（注释长度无法自洽）→ 放弃，宁可跳过不改坏。
    #[test]
    fn zip_abandons_file_with_junk_after_eocd() {
        let mut data = zip_fixture();
        data.extend_from_slice(&[0u8; 8]);
        assert!(Format::Zip.normalize(&mut data, 1_791_458_952).is_err());
    }

    /// gzip：mtime 字段 4..8 写 epoch LE；负值与超 u32 值写 0。
    #[test]
    fn gzip_rewrites_mtime_field() {
        let mut data = vec![0x1f, 0x8b, 8, 0, 0xAA, 0xBB, 0xCC, 0xDD, 0xFF];
        Format::Gzip.normalize(&mut data, 1_791_458_952).unwrap();
        assert_eq!(&data[4..8], &1_791_458_952_u32.to_le_bytes());

        let mut data = vec![0x1f, 0x8b, 8, 0, 0xAA, 0xBB, 0xCC, 0xDD];
        Format::Gzip.normalize(&mut data, -5).unwrap();
        assert_eq!(&data[4..8], &0_u32.to_le_bytes());

        let mut data = vec![0x1f, 0x8b, 8, 0, 0xAA, 0xBB, 0xCC, 0xDD];
        Format::Gzip
            .normalize(&mut data, i64::from(u32::MAX) + 1)
            .unwrap();
        assert_eq!(&data[4..8], &0_u32.to_le_bytes());

        let mut data = vec![0x1f, 0x8b, 8, 0, 0xAA, 0xBB, 0xCC, 0xDD];
        Format::Gzip
            .normalize(&mut data, i64::from(u32::MAX))
            .unwrap();
        assert_eq!(&data[4..8], &u32::MAX.to_le_bytes());
    }

    /// gzip 幂等 + FLG/FEXTRA 无关性：mtime 恒在 4..8，后续字节原样；
    /// 首次有改写、重放 changed=false。
    #[test]
    fn gzip_is_idempotent_and_ignores_extra_fields() {
        let mut data = vec![0x1f, 0x8b, 8, 0x08, 0, 0, 0, 0, 0x00, 0x03];
        data.extend_from_slice(b"some extra and name bytes");
        let tail = data[9..].to_vec();
        assert!(Format::Gzip.normalize(&mut data, 1_791_458_952).unwrap());
        let once = data.clone();
        assert!(!Format::Gzip.normalize(&mut data, 1_791_458_952).unwrap());
        assert_eq!(data, once);
        assert_eq!(&data[9..], &tail);
    }

    /// gzip：头部不足 8 字节 → 放弃。
    #[test]
    fn gzip_rejects_truncated_header() {
        let mut data = vec![0x1f, 0x8b, 8];
        assert!(Format::Gzip.normalize(&mut data, 1).is_err());
    }

    /// 识别表：ar/zip/gzip magic 命中对应分支，zip 不在 offset 0 不识别，
    /// 无关字节不识别（路径因子不命中时的回落通道）。
    #[test]
    fn detection_matches_documented_magic_rules() {
        let none = Path::new("misc.bin");
        assert_eq!(Format::detect(b"!<arch>\n", none), Some(Format::Ar));
        assert_eq!(Format::detect(b"PK\x03\x04rest", none), Some(Format::Zip));
        assert_eq!(
            Format::detect(b"\x1f\x8b\x08\x00", none),
            Some(Format::Gzip)
        );
        assert_eq!(Format::detect(b"PK\x05\x06", none), None);
        assert_eq!(Format::detect(b"junkPK\x03\x04", none), None);
        assert_eq!(Format::detect(b"", none), None);
    }

    /// 识别反例：1f 8b 开头但 CM≠8 不是 gzip（防非 gzip 文件被误识别后
    /// 覆写 mtime 载荷），仅 2 字节无 CM 位也不识别。
    #[test]
    fn gzip_detection_requires_deflate_method_byte() {
        let none = Path::new("misc.bin");
        assert_eq!(Format::detect(&[0x1f, 0x8b, 0x00, 0x00], none), None);
        assert_eq!(Format::detect(b"\x1f\x8bXX", none), None);
        assert_eq!(Format::detect(b"\x1f\x8b", none), None);
        // CM=8（deflate）正常识别
        assert_eq!(
            Format::detect(&[0x1f, 0x8b, 8, 0x00], none),
            Some(Format::Gzip)
        );
    }

    /// 路径键控：DESCRIPTION 认领（含 Built 行）、无 Built 行与非 UTF-8 的
    /// 同名文件不认领；.html 大小写不敏感且须含 javadoc 标记；package.rds
    /// 须 Meta 父目录 + gzip magic，非 gzip 或挪窝不认领。
    #[test]
    fn path_keyed_detection_rules() {
        let desc = b"Package: x\nBuilt: R 4.0.5; a; 2026-10-11 07:11:17 UTC; unix\n".as_slice();
        assert_eq!(
            Format::detect(desc, Path::new("usr/lib64/R/library/jsonlite/DESCRIPTION")),
            Some(Format::RDescription)
        );
        assert_eq!(
            Format::detect(b"Package: x\n", Path::new("lib/DESCRIPTION")),
            None
        );
        assert_eq!(
            Format::detect(&[0xff, 0xfe, 0x00], Path::new("lib/DESCRIPTION")),
            None
        );
        // Latin-1 的 DESCRIPTION 即便含 Built 行也被 UTF-8 门禁拒绝
        //（R 元数据恒 UTF-8，该门禁与 javadoc 的字节级窗口互不通用）
        assert_eq!(
            Format::detect(
                b"Package: x\nBuilt: R 4.0.5; a; \xD6l 2026-10-11 07:11:17 UTC; unix\n",
                Path::new("lib/DESCRIPTION")
            ),
            None
        );

        let html = b"<html><!-- Generated by javadoc (1.8.0_462) on x -->";
        assert_eq!(
            Format::detect(html, Path::new("doc/AllClasses.html")),
            Some(Format::JavadocHtml)
        );
        assert_eq!(
            Format::detect(html, Path::new("doc/INDEX.HTML")),
            Some(Format::JavadocHtml)
        );
        assert_eq!(Format::detect(html, Path::new("doc/readme.htm")), None);
        assert_eq!(
            Format::detect(b"<html><body>", Path::new("doc/x.html")),
            None
        );

        assert_eq!(
            Format::detect(&[0x1f, 0x8b, 8, 0], Path::new("lib/p/Meta/package.rds")),
            Some(Format::RPkgRds)
        );
        assert_eq!(
            Format::detect(b"X\n\x00\x00\x00\x03", Path::new("lib/p/Meta/package.rds")),
            None,
            "非 gzip 的 package.rds 不认领"
        );
        assert_eq!(
            Format::detect(&[0x1f, 0x8b, 8, 0], Path::new("lib/p/cache/package.rds")),
            Some(Format::Gzip),
            "非 Meta 父目录不认领路径因子，回落 magic 通道"
        );
        assert_eq!(
            Format::detect(&[0x1f, 0x8b, 8, 0], Path::new("lib/p/Meta/ns.rds")),
            Some(Format::Gzip),
            "非 package.rds 的 Meta 序列化文件只走 gzip 头通道"
        );
    }

    /// 路径键控扫描上限：超过 4MiB 的同形态文件不认领（防误扫大文件）。
    #[test]
    fn path_keyed_scan_respects_size_cap() {
        let mut big = b"Package: x\nBuilt: R 4.0.5; a; 2026-10-11 07:11:17 UTC; unix\n".to_vec();
        big.resize(4 * 1024 * 1024 + 1, b'\n');
        assert_eq!(Format::detect(&big, Path::new("lib/DESCRIPTION")), None);
        big.truncate(4 * 1024 * 1024);
        assert_eq!(
            Format::detect(&big, Path::new("lib/DESCRIPTION")),
            Some(Format::RDescription)
        );
    }

    /// Latin-1 javadoc HTML 夹具：生成注释纯 ASCII，正文含 Latin-1 高字节
    /// （"Ölfässer" 的 Latin-1 编码字节）。
    fn latin1_javadoc_html() -> Vec<u8> {
        let mut v = b"<!DOCTYPE HTML>\n".to_vec();
        v.extend_from_slice(
            b"<!-- Generated by javadoc (1.8.0_462) on Sun Oct 11 15:04:49 CST 2026 -->\n",
        );
        v.extend_from_slice(b"<html><body>\n<p>");
        v.extend_from_slice(&[0xD6, 0x6C, 0x66, 0xE4, 0x73, 0x73, 0x65, 0x72]);
        v.extend_from_slice(b"</p>\n</body></html>\n");
        v
    }

    /// Latin-1 javadoc HTML（注释窗口纯 ASCII、正文含高字节）：detect 认领、
    /// 注释段换锚归一且注释外字节原样；归一结果仍被认领、二次运行字节不变。
    #[test]
    fn javadoc_latin1_file_is_claimed_and_normalized() {
        let original = latin1_javadoc_html();
        assert_eq!(
            Format::detect(&original, Path::new("doc/help.html")),
            Some(Format::JavadocHtml)
        );
        let mut data = original.clone();
        assert!(Format::JavadocHtml
            .normalize(&mut data, 1_791_458_952)
            .unwrap());
        let head = b"<!DOCTYPE HTML>\n<!-- Generated by javadoc (1.8.0_462) on 2026-10-08 11:29:12 UTC -->\n<html><body>\n<p>";
        assert!(data.starts_with(head));
        let orig_head = b"<!DOCTYPE HTML>\n<!-- Generated by javadoc (1.8.0_462) on Sun Oct 11 15:04:49 CST 2026 -->\n<html><body>\n<p>";
        // 注释变长段摘除后尺寸缩小，注释外尾段（含 Latin-1 高字节）必须逐字节原样
        assert_eq!(&data[head.len()..], &original[orig_head.len()..]);

        let once = data.clone();
        assert_eq!(
            Format::detect(&once, Path::new("doc/help.html")),
            Some(Format::JavadocHtml)
        );
        assert!(!Format::JavadocHtml
            .normalize(&mut data, 1_791_458_952)
            .unwrap());
        assert_eq!(data, once);
    }

    /// javadoc 门禁的 ASCII 谓词边界：窗口（标记到 `-->`）内高字节不认领，
    /// 同一高字节在窗口外（正文）不影响认领。
    #[test]
    fn javadoc_gate_ascii_window_boundary() {
        let inside =
            b"<!-- Generated by javadoc (1.8.0_462) on Su\xFCn Oct 11 15:04:49 CST 2026 -->\n";
        assert_eq!(Format::detect(inside, Path::new("doc/x.html")), None);

        let outside = b"<!-- Generated by javadoc (1.8.0_462) on Sun Oct 11 15:04:49 CST 2026 -->\n<p>Su\xFCn</p>\n";
        assert_eq!(
            Format::detect(outside, Path::new("doc/x.html")),
            Some(Format::JavadocHtml)
        );
    }
}
