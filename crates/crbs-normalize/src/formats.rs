// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 按文件内容或路径识别格式，将内嵌的时间戳改写为指定值；解析失败的文件由
//! 调用方整体放弃，保持原样。

use std::ffi::OsStr;
use std::path::Path;

use crate::rds;
use crate::text;

use crate::dos::epoch_to_dos;

const AR_MAGIC: &[u8] = b"!<arch>\n";

const AR_HEADER_LEN: usize = 60;

const AR_ID_ZERO: &[u8; 6] = b"0     ";

const ZIP_LOCAL_MAGIC: &[u8] = b"PK\x03\x04";

const ZIP_CENTRAL_MAGIC: &[u8] = b"PK\x01\x02";

const ZIP_EOCD_MAGIC: &[u8] = b"PK\x05\x06";

const ZIP_EOCD_SCAN: usize = 22 + 65_535;

const ZIP_CENTRAL_HDR: usize = 46;

const ZIP_EOCD_HDR: usize = 22;

const GZIP_MAGIC: &[u8] = &[0x1f, 0x8b];

/// 按路径识别的格式只认文件不超过 4 MiB 的输入：超过即整体不认领
///（detect_by_path 返回 None），避免在大文件上浪费处理时间。
const MAX_PATH_KEYED_SCAN: usize = 4 * 1024 * 1024;

/// 前三个按文件内容识别，后三个按路径识别。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    Ar,
    Zip,
    Gzip,

    RDescription,

    RPkgRds,

    JavadocHtml,
}

impl Format {
    /// 识别顺序为先路径、后内容。package.rds 同时也符合 gzip 特征，必须先按路径
    /// 识别，交给内容级处理。
    pub(crate) fn detect(data: &[u8], rel_path: &Path) -> Option<Format> {
        Self::detect_by_path(data, rel_path).or_else(|| Self::detect_by_magic(data))
    }

    fn detect_by_path(data: &[u8], rel_path: &Path) -> Option<Format> {
        if data.len() > MAX_PATH_KEYED_SCAN {
            return None;
        }
        let name = rel_path.file_name()?;
        if name == OsStr::new("DESCRIPTION") {
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
            return text::javadoc_gate(data).then_some(Format::JavadocHtml);
        }
        None
    }

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

    /// 返回 Ok(true) 表示改写了字节；Err 表示格式解析失败，调用方不得写回该文件。
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

fn is_gzip_deflate(data: &[u8]) -> bool {
    data.starts_with(GZIP_MAGIC) && data.get(2) == Some(&8)
}

/// epoch 超出 u32 可表示的范围时写 0；gzip 规范中 0 表示该文件没有时间戳。
pub(crate) fn gzip_mtime_u32(epoch: i64) -> u32 {
    if (0..=i64::from(u32::MAX)).contains(&epoch) {
        epoch as u32
    } else {
        0
    }
}

fn ascii_field(data: &[u8], range: std::ops::Range<usize>) -> Result<&str, String> {
    let raw = data
        .get(range.clone())
        .ok_or_else(|| format!("field {range:?} out of bounds"))?;
    let text = std::str::from_utf8(raw).map_err(|_| format!("field {range:?} not ASCII"))?;
    Ok(text.trim_end_matches(' '))
}

fn le_u16(data: &[u8], off: usize) -> Result<u16, String> {
    let hi = off
        .checked_add(2)
        .ok_or_else(|| format!("offset {off} overflow"))?;
    let pair = data
        .get(off..hi)
        .ok_or_else(|| format!("u16 at {off} out of bounds"))?;
    Ok(u16::from_le_bytes([pair[0], pair[1]]))
}

fn le_u32(data: &[u8], off: usize) -> Result<u32, String> {
    let hi = off
        .checked_add(4)
        .ok_or_else(|| format!("offset {off} overflow"))?;
    let quad = data
        .get(off..hi)
        .ok_or_else(|| format!("u32 at {off} out of bounds"))?;
    Ok(u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]]))
}

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

/// 依次改写每个成员头：mtime 设为 epoch，uid/gid 固定为 0。uid/gid 必须改写——
/// strip 重写 .a 文件时会写入当前构建用户的信息，原值随环境变化。
fn normalize_ar(data: &mut [u8], epoch: i64) -> Result<bool, String> {
    let mut field = [b' '; 12];
    let text = epoch.to_string();

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

        off = data_end.saturating_add(size & 1);
    }
    Ok(changed)
}

/// 从文件末尾查找 zip 的结束记录，确认文件清单与条目数一致后，改写本地头和
/// 清单中的时间字段。
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

        if data.get(local_off..local_off + 4) != Some(ZIP_LOCAL_MAGIC) {
            return Err(format!(
                "bad zip local header at {local_off} (entry {index})"
            ));
        }
        changed |= write_bytes(data, local_off + 10, &time_bytes)?;
        changed |= write_bytes(data, local_off + 12, &date_bytes)?;
    }

    if off != eocd {
        return Err(format!(
            "zip central directory {total_entries} entries do not span [{cd_offset}, {eocd})"
        ));
    }
    Ok(changed)
}

/// 只改写第一个成员头的 mtime（固定为第 4 至 8 字节的 LE u32）；epoch 超出 u32
/// 范围时写 0。
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

    /// 手工构造的 ar 测试数据，mtime/uid/gid 为无效值。
    fn ar_fixture(mtime_text: &[u8; 12]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(AR_MAGIC);
        v.extend_from_slice(b"member.txt/     ");
        v.extend_from_slice(mtime_text);
        v.extend_from_slice(b"987   ");
        v.extend_from_slice(b"989   ");
        v.extend_from_slice(b"100644  ");
        v.extend_from_slice(b"5         ");
        v.extend_from_slice(b"`\n");
        v.extend_from_slice(b"hello");
        v.push(b'\n');
        v
    }

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

    #[test]
    fn ar_is_idempotent() {
        let mut data = ar_fixture(b"1700000000  ");
        assert!(Format::Ar.normalize(&mut data, 1_791_458_952).unwrap());
        let once = data.clone();
        assert!(!Format::Ar.normalize(&mut data, 1_791_458_952).unwrap());
        assert_eq!(data, once);
    }

    #[test]
    fn ar_rewrites_long_name_and_symbol_index_members() {
        let mut v = Vec::new();
        v.extend_from_slice(AR_MAGIC);

        v.extend_from_slice(b"//              ");
        v.extend_from_slice(b"1111111111  ");
        v.extend_from_slice(b"987   ");
        v.extend_from_slice(b"989   ");
        v.extend_from_slice(b"0       ");
        v.extend_from_slice(b"8         ");
        v.extend_from_slice(b"`\n");
        v.extend_from_slice(b"nameidx/");

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

    #[test]
    fn ar_rejects_epoch_wider_than_field() {
        let mut data = ar_fixture(b"1700000000  ");
        assert!(Format::Ar.normalize(&mut data, i64::MIN).is_err());
    }

    /// 手工构造的 zip 测试数据，time/date 为无效的非零值。
    fn zip_fixture() -> Vec<u8> {
        let name = b"f.txt";
        let mut v = Vec::new();

        v.extend_from_slice(ZIP_LOCAL_MAGIC);
        v.extend_from_slice(&[0u8; 6]);
        v.extend_from_slice(&0x1111_u16.to_le_bytes());
        v.extend_from_slice(&0x2222_u16.to_le_bytes());
        v.extend_from_slice(&[0u8; 12]);
        v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        v.extend_from_slice(&0_u16.to_le_bytes());
        v.extend_from_slice(name);
        v.extend_from_slice(b"body");

        let cd_offset = v.len() as u32;
        v.extend_from_slice(ZIP_CENTRAL_MAGIC);
        v.extend_from_slice(&[0u8; 8]);
        v.extend_from_slice(&0x3333_u16.to_le_bytes());
        v.extend_from_slice(&0x4444_u16.to_le_bytes());
        v.extend_from_slice(&[0u8; 12]);
        v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        v.extend_from_slice(&0_u16.to_le_bytes());
        v.extend_from_slice(&0_u16.to_le_bytes());
        v.extend_from_slice(&0_u16.to_le_bytes());
        v.extend_from_slice(&0_u16.to_le_bytes());
        v.extend_from_slice(&0_u32.to_le_bytes());
        v.extend_from_slice(&0_u32.to_le_bytes());
        v.extend_from_slice(name);
        let cd_size = v.len() - cd_offset as usize;

        v.extend_from_slice(ZIP_EOCD_MAGIC);
        v.extend_from_slice(&0_u16.to_le_bytes());
        v.extend_from_slice(&0_u16.to_le_bytes());
        v.extend_from_slice(&1_u16.to_le_bytes());
        v.extend_from_slice(&1_u16.to_le_bytes());
        v.extend_from_slice(&(cd_size as u32).to_le_bytes());
        v.extend_from_slice(&cd_offset.to_le_bytes());
        v.extend_from_slice(&0_u16.to_le_bytes());
        v
    }

    #[test]
    fn zip_rewrites_central_and_local_time_fields() {
        let mut data = zip_fixture();
        Format::Zip.normalize(&mut data, 1_791_458_952).unwrap();
        let (dos_date, dos_time) = (23_880_u16, 23_462_u16);
        assert_eq!(&data[10..12], &dos_time.to_le_bytes());
        assert_eq!(&data[12..14], &dos_date.to_le_bytes());
        let cd = 30 + 5 + 4;
        assert_eq!(&data[cd + 12..cd + 14], &dos_time.to_le_bytes());
        assert_eq!(&data[cd + 14..cd + 16], &dos_date.to_le_bytes());
        assert_eq!(&data[30..35], b"f.txt");
    }

    #[test]
    fn zip_is_idempotent() {
        let mut data = zip_fixture();
        assert!(Format::Zip.normalize(&mut data, 1_791_458_952).unwrap());
        let once = data.clone();
        assert!(!Format::Zip.normalize(&mut data, 1_791_458_952).unwrap());
        assert_eq!(data, once);
    }

    #[test]
    fn zip_abandons_entry_count_short_of_directory() {
        let mut data = zip_fixture();
        let eocd = data.len() - 22;

        data[eocd + 8..eocd + 12].copy_from_slice(&0_u32.to_le_bytes());
        assert!(Format::Zip.normalize(&mut data, 1_791_458_952).is_err());
    }

    #[test]
    fn zip_rejects_malformed_structures() {
        let mut no_eocd = zip_fixture();
        no_eocd.truncate(no_eocd.len() - 22);
        assert!(Format::Zip.normalize(&mut no_eocd, 1).is_err());

        let mut bad_cd = zip_fixture();
        let eocd = bad_cd.len() - 22;

        bad_cd[eocd + 16..eocd + 20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Format::Zip.normalize(&mut bad_cd, 1).is_err());

        let mut bad_local = zip_fixture();
        bad_local[0] = b'X';
        assert!(Format::Zip.normalize(&mut bad_local, 1).is_err());
    }

    #[test]
    fn zip_abandons_file_with_junk_after_eocd() {
        let mut data = zip_fixture();
        data.extend_from_slice(&[0u8; 8]);
        assert!(Format::Zip.normalize(&mut data, 1_791_458_952).is_err());
    }

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

    #[test]
    fn gzip_rejects_truncated_header() {
        let mut data = vec![0x1f, 0x8b, 8];
        assert!(Format::Gzip.normalize(&mut data, 1).is_err());
    }

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

    #[test]
    fn gzip_detection_requires_deflate_method_byte() {
        let none = Path::new("misc.bin");
        assert_eq!(Format::detect(&[0x1f, 0x8b, 0x00, 0x00], none), None);
        assert_eq!(Format::detect(b"\x1f\x8bXX", none), None);
        assert_eq!(Format::detect(b"\x1f\x8b", none), None);

        assert_eq!(
            Format::detect(&[0x1f, 0x8b, 8, 0x00], none),
            Some(Format::Gzip)
        );
    }

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

    /// 正文包含 Latin-1 高字节的 javadoc HTML 测试数据。
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
