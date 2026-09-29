// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! RFC 1951 deflate 裸流解码 + stored 块重编码 + CRC32（IEEE）：package.rds
//! 内容级归一化的纯 std 支撑。取舍：解码按 puff 算法逐位走表，未做
//! Huffman 快表，性能上限为元数据级小文件（MB 级以内）；解码正确性由调用
//! 方用容器自带 CRC32 兜底验证，错流一律 Err 由上层整体放弃。

/// CRC32 查表（反射多项式 0xEDB88320），const 求值免运行期初始化。
const fn make_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

const CRC_TABLE: [u32; 256] = make_crc_table();

/// CRC32（gzip 尾部校验字段口径）。
pub(crate) fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = CRC_TABLE[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

/// 位读取器：LSB 在前（deflate 位序）；缓冲按整字节填入，不越位。
struct BitReader<'a> {
    data: &'a [u8],
    /// 下一个未消费字节下标
    next: usize,
    /// 位缓冲（低位先出），cnt 为有效位数
    buf: u32,
    cnt: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> BitReader<'a> {
        BitReader {
            data,
            next: 0,
            buf: 0,
            cnt: 0,
        }
    }

    /// 读 n 位（n ≤ 16：调用方最大请求为 13 位距离 extra）；流尽即格式损坏。
    fn bits(&mut self, n: u32) -> Result<u32, String> {
        while self.cnt < n {
            let byte = *self
                .data
                .get(self.next)
                .ok_or_else(|| "deflate stream truncated".to_string())?;
            self.next += 1;
            self.buf |= u32::from(byte) << self.cnt;
            self.cnt += 8;
        }
        let value = self.buf & ((1u32 << n) - 1);
        self.buf >>= n;
        self.cnt -= n;
        Ok(value)
    }

    fn bit(&mut self) -> Result<u32, String> {
        self.bits(1)
    }

    /// 丢弃当前字节内剩余位并归退缓冲整字节，返回对齐后的流下标——
    /// stored 块的 LEN/数据必须按字节序从流上直读。
    fn align(&mut self) -> usize {
        let drop = self.cnt % 8;
        self.cnt -= drop;
        self.next -= (self.cnt / 8) as usize;
        self.buf = 0;
        self.cnt = 0;
        self.next
    }

    /// 直设流下标（stored 块消费后跳转）。
    fn seek(&mut self, pos: usize) {
        self.next = pos;
        self.buf = 0;
        self.cnt = 0;
    }
}

/// 规范 Huffman 最大码长（RFC 1951 固定上界）。
const MAX_BITS: usize = 15;

/// 规范 Huffman 解码表：码长计数 + 同码长内按符号升序的符号表（puff 口径）。
struct Huffman {
    counts: [u16; MAX_BITS + 1],
    symbols: [u16; 288],
}

/// 由码长表构建解码表（动态树口径）：超订阅即错误；不完备仅在全部码长
/// ≤1（单码退化树，zlib 对距离树合法产出）时放行。
fn huffman_build(lengths: &[u8]) -> Result<Huffman, String> {
    huffman_build_inner(lengths, true)
}

/// 固定表构建：表为 RFC 1951 规范常量（固定距离树天然不完备：30/32 个
/// 5 位码），跳过完备性检查。
fn huffman_build_trusted(lengths: &[u8]) -> Result<Huffman, String> {
    huffman_build_inner(lengths, false)
}

fn huffman_build_inner(lengths: &[u8], check_incomplete: bool) -> Result<Huffman, String> {
    let mut counts = [0u16; MAX_BITS + 1];
    for &l in lengths {
        if l as usize > MAX_BITS {
            return Err(format!("huffman code length {l} exceeds {MAX_BITS}"));
        }
        counts[l as usize] += 1;
    }
    counts[0] = 0;
    let mut left: i32 = 1;
    for &count in &counts[1..] {
        left <<= 1;
        left -= i32::from(count);
        if left < 0 {
            return Err("over-subscribed huffman code".to_string());
        }
    }
    let complete = left == 0;
    if check_incomplete && !complete && lengths.iter().filter(|&&l| l != 0).count() > 1 {
        return Err("incomplete huffman code with multiple symbols".to_string());
    }
    let mut offsets = [0u16; MAX_BITS + 1];
    for len in 1..MAX_BITS {
        offsets[len + 1] = offsets[len] + counts[len];
    }
    let mut symbols = [0u16; 288];
    for (sym, &l) in lengths.iter().enumerate() {
        if l != 0 {
            symbols[offsets[l as usize] as usize] = sym as u16;
            offsets[l as usize] += 1;
        }
    }
    Ok(Huffman { counts, symbols })
}

/// 逐位走规范码树（puff decode）：一位一比较，无需建快表。
fn huffman_decode(h: &Huffman, br: &mut BitReader<'_>) -> Result<u16, String> {
    let mut code: i32 = 0;
    let mut first: i32 = 0;
    let mut index: i32 = 0;
    for len in 1..=MAX_BITS {
        code |= br.bit()? as i32;
        let count = i32::from(h.counts[len]);
        if code - count < first {
            return Ok(h.symbols[(index + (code - first)) as usize]);
        }
        index += count;
        first = (first + count) << 1;
        code <<= 1;
    }
    Err("invalid huffman code in stream".to_string())
}

/// 长度符号 257..=285 的基础长度（285 恰为 258，无 extra）。
const LENGTH_BASE: [usize; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
/// 长度符号的 extra 位数。
const LENGTH_EXTRA: [u32; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
/// 距离符号 0..=29 的基础距离。
const DIST_BASE: [usize; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
/// 距离符号的 extra 位数。
const DIST_EXTRA: [u32; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// 解码完整 deflate 裸流；输出超 `cap` 即 Err（防御压缩炸弹），块类型 11、
/// 越界距离、截断流均 Err。
pub(crate) fn inflate(data: &[u8], cap: usize) -> Result<Vec<u8>, String> {
    let mut br = BitReader::new(data);
    let mut out: Vec<u8> = Vec::new();
    loop {
        let last = br.bit()?;
        match br.bits(2)? {
            0 => inflate_stored(&mut br, &mut out, cap)?,
            1 => {
                // 固定 Huffman 表：字面量/长度按符号区间定长，距离恒 5 位
                let mut lengths = [0u8; 288];
                for (sym, len) in lengths.iter_mut().enumerate() {
                    *len = match sym {
                        0..=143 => 8,
                        144..=255 => 9,
                        256..=279 => 7,
                        _ => 8,
                    };
                }
                let litlen = huffman_build_trusted(&lengths)?;
                let dist = huffman_build_trusted(&[5u8; 30])?;
                inflate_block(&mut br, &mut out, cap, &litlen, &dist)?;
            }
            2 => inflate_dynamic(&mut br, &mut out, cap)?,
            _ => return Err("reserved deflate block type 11".to_string()),
        }
        if last == 1 {
            break;
        }
    }
    Ok(out)
}

/// stored 块（BTYPE=00）：对齐后 LEN/NLEN 反码自校验 + 原样拷贝。
fn inflate_stored(br: &mut BitReader<'_>, out: &mut Vec<u8>, cap: usize) -> Result<(), String> {
    let pos = br.align();
    let hdr = br
        .data
        .get(pos..pos + 4)
        .ok_or_else(|| "stored block header truncated".to_string())?;
    let len = u16::from_le_bytes([hdr[0], hdr[1]]);
    let nlen = u16::from_le_bytes([hdr[2], hdr[3]]);
    if len != !nlen {
        return Err("stored block LEN/NLEN mismatch".to_string());
    }
    let body = br
        .data
        .get(pos + 4..pos + 4 + usize::from(len))
        .ok_or_else(|| "stored block data truncated".to_string())?;
    if out.len() + body.len() > cap {
        return Err("inflated output exceeds cap".to_string());
    }
    out.extend_from_slice(body);
    br.seek(pos + 4 + usize::from(len));
    Ok(())
}

/// dynamic 块（BTYPE=10）：码长码树 + 两棵符号树逐段构建后进入数据解码。
fn inflate_dynamic(br: &mut BitReader<'_>, out: &mut Vec<u8>, cap: usize) -> Result<(), String> {
    // 码长按此固定次序传输
    const ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let nlen = br.bits(5)? as usize + 257;
    let ndist = br.bits(5)? as usize + 1;
    let ncode = br.bits(4)? as usize + 4;
    if nlen > 286 || ndist > 30 {
        return Err("dynamic block symbol counts out of range".to_string());
    }
    let mut cl_lengths = [0u8; 19];
    for &idx in ORDER.iter().take(ncode) {
        cl_lengths[idx] = br.bits(3)? as u8;
    }
    let cl_tree = huffman_build(&cl_lengths)?;

    let mut lengths = [0u8; 316]; // nlen + ndist 的上界
    let mut index = 0;
    while index < nlen + ndist {
        match huffman_decode(&cl_tree, br)? {
            sym @ 0..=15 => {
                lengths[index] = sym as u8;
                index += 1;
            }
            16 => {
                if index == 0 {
                    return Err("code-length repeat with no previous".to_string());
                }
                let prev = lengths[index - 1];
                repeat_length(
                    &mut lengths[..nlen + ndist],
                    &mut index,
                    prev,
                    3 + br.bits(2)?,
                )?;
            }
            17 => repeat_length(&mut lengths[..nlen + ndist], &mut index, 0, 3 + br.bits(3)?)?,
            18 => repeat_length(
                &mut lengths[..nlen + ndist],
                &mut index,
                0,
                11 + br.bits(7)?,
            )?,
            _ => return Err("invalid code-length symbol".to_string()),
        }
    }
    let litlen = huffman_build(&lengths[..nlen])?;
    let dist = huffman_build(&lengths[nlen..nlen + ndist])?;
    inflate_block(br, out, cap, &litlen, &dist)
}

/// 码长重复填充（16/17/18 号符号共用）；越过 nlen+ndist 边界即格式损坏。
fn repeat_length(
    lengths: &mut [u8],
    index: &mut usize,
    value: u8,
    count: u32,
) -> Result<(), String> {
    let count = count as usize;
    if *index + count > lengths.len() {
        return Err("code-length repeat overruns symbol counts".to_string());
    }
    lengths[*index..*index + count].fill(value);
    *index += count;
    Ok(())
}

/// Huffman 数据块共享解码循环：字面量直出、256 终止、长度/距离对回引拷贝
/// （逐字节以正确处理重叠回引）。
fn inflate_block(
    br: &mut BitReader<'_>,
    out: &mut Vec<u8>,
    cap: usize,
    litlen: &Huffman,
    dist: &Huffman,
) -> Result<(), String> {
    loop {
        match huffman_decode(litlen, br)? {
            sym @ 0..=255 => {
                if out.len() >= cap {
                    return Err("inflated output exceeds cap".to_string());
                }
                out.push(sym as u8);
            }
            256 => return Ok(()),
            sym @ 257..=285 => {
                let idx = (sym - 257) as usize;
                let len = LENGTH_BASE[idx] + br.bits(LENGTH_EXTRA[idx])? as usize;
                let dsym = huffman_decode(dist, br)? as usize;
                if dsym >= 30 {
                    return Err(format!("invalid distance symbol {dsym}"));
                }
                let back = DIST_BASE[dsym] + br.bits(DIST_EXTRA[dsym])? as usize;
                if back > out.len() {
                    return Err(format!("distance {back} beyond output start {}", out.len()));
                }
                if out.len() + len > cap {
                    return Err("inflated output exceeds cap".to_string());
                }
                let start = out.len() - back;
                for k in 0..len {
                    let byte = out[start + k];
                    out.push(byte);
                }
            }
            sym => return Err(format!("invalid literal/length symbol {sym}")),
        }
    }
}

/// stored 块重编码：无需 Huffman 编码器，块 ≤ 65535 字节，流尺寸比原压缩
/// 形态大但双侧同形即可确定。
pub(crate) fn deflate_stored(data: &[u8]) -> Vec<u8> {
    let block_count = data.len().div_ceil(65_535).max(1);
    let mut out = Vec::with_capacity(data.len() + block_count * 5);
    let mut off = 0;
    loop {
        let chunk = (data.len() - off).min(65_535);
        let final_block = off + chunk == data.len();
        out.push(u8::from(final_block)); // BFINAL | BTYPE=00
        let len = chunk as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(&data[off..off + chunk]);
        off += chunk;
        if final_block {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// CRC32 已知向量：空串、RFC 1952 规范测试串 "123456789"、"hello"。
    #[test]
    fn crc32_known_vectors() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b"hello"), 0x3610_A686);
    }

    const PLAINTEXT_HEX: &str = "7061636b6167652e726473206275696c74205220342e302e353b207838365f36342d70632d6c696e75782d676e753b20323032362d30312d30322030333a30343a3035205554433b20756e69780a7061636b6167652e726473206275696c74205220342e302e353b207838365f36342d70632d6c696e75782d676e753b20323032362d30312d30322030333a30343a3035205554433b20756e69780a7061636b6167652e726473206275696c74205220342e302e353b207838365f36342d70632d6c696e75782d676e753b20323032362d30312d30322030333a30343a3035205554433b20756e69780a5061636b616765643a20323032302d30352d30362030373a30383a3039205554433b206a65726f656e202d2d2064657465726d696e697374696320736f75726365206d657461646174610a7461696c2062797465732030313233343536373839";

    /// 三种块编码的真实 deflate 流（zlib 产出：动态/固定/stored），同明文
    /// 必须解码一致；覆盖动态码长重复（16/17/18）与 LZ77 重叠回引。
    #[test]
    fn inflate_covers_all_block_codings() {
        let plain = hex(PLAINTEXT_HEX);
        // 动态 Huffman（zlib level 9）
        let dynamic = hex("cdcc4b0a83301000d0bda7980b8c8c31891a97bd4029edbac424485a8d920fd8db97e225ba7fbc5d9bb79e5d1d6d82a9f825c30d784db518e1e8e55372dc0d2e3e9403e7504660c4245283c4805a455c9180c7fd324209fea8f63fdeaee766d5cf11924092409da25ed170ba978b9b0b8008d66517571f7ccade40da4a340e5697b5d5595759fb05a64f7609a8612d17b2eb872f");
        // 固定 Huffman（zlib Z_FIXED）
        let fixed = hex("2b484cce4e4c4fd52b4a2956482acdcc2951085230d133d033b556a8b0308b3733d12d48d6cdc9cc2badd04dcf2bb55630323032d33530d43530523030b63230b1323055080d71b65628cdcbace02a18c4a605404c4bb102a933d03530d53530533030b732b0b032b084a8cb4a2dca4fcd53d0d55548492d492dcacdcccb2c2ec94c5628ce2f2d4a4e55c84d2d494c492c49e42a49cccc5148aa2c492d563030343236313533b7b00400");
        // stored 块（zlib level 0）
        let stored = hex("014a01b5fe7061636b6167652e726473206275696c74205220342e302e353b207838365f36342d70632d6c696e75782d676e753b20323032362d30312d30322030333a30343a3035205554433b20756e69780a7061636b6167652e726473206275696c74205220342e302e353b207838365f36342d70632d6c696e75782d676e753b20323032362d30312d30322030333a30343a3035205554433b20756e69780a7061636b6167652e726473206275696c74205220342e302e353b207838365f36342d70632d6c696e75782d676e753b20323032362d30312d30322030333a30343a3035205554433b20756e69780a5061636b616765643a20323032302d30352d30362030373a30383a3039205554433b206a65726f656e202d2d2064657465726d696e697374696320736f75726365206d657461646174610a7461696c2062797465732030313233343536373839");
        assert_eq!(inflate(&dynamic, 1 << 20).unwrap(), plain);
        assert_eq!(inflate(&fixed, 1 << 20).unwrap(), plain);
        assert_eq!(inflate(&stored, 1 << 20).unwrap(), plain);
    }

    /// inflate 输出上限：cap 小于真实尺寸 → Err（压缩炸弹防御）。
    #[test]
    fn inflate_respects_output_cap() {
        let stored = hex("014a01b5fe7061636b6167652e726473206275696c74205220342e302e353b207838365f36342d70632d6c696e75782d676e753b20323032362d30312d30322030333a30343a3035205554433b20756e69780a7061636b6167652e726473206275696c74205220342e302e353b207838365f36342d70632d6c696e75782d676e753b20323032362d30312d30322030333a30343a3035205554433b20756e69780a7061636b6167652e726473206275696c74205220342e302e353b207838365f36342d70632d6c696e75782d676e753b20323032362d30312d30322030333a30343a3035205554433b20756e69780a5061636b616765643a20323032302d30352d30362030373a30383a3039205554433b206a65726f656e202d2d2064657465726d696e697374696320736f75726365206d657461646174610a7461696c2062797465732030313233343536373839");
        assert!(inflate(&stored, 100).is_err());
    }

    /// 畸形流：截断、LEN/NLEN 反码不符、保留块类型 11 均拒绝。
    #[test]
    fn inflate_rejects_malformed_streams() {
        let stored = hex("014a01b5fe7061636b6167652e726473206275696c74205220342e302e353b207838365f36342d70632d6c696e75782d676e753b20323032362d30312d30322030333a30343a3035205554433b20756e69780a7061636b6167652e726473206275696c74205220342e302e353b207838365f36342d70632d6c696e75782d676e753b20323032362d30312d30322030333a30343a3035205554433b20756e69780a7061636b6167652e726473206275696c74205220342e302e353b207838365f36342d70632d6c696e75782d676e753b20323032362d30312d30322030333a30343a3035205554433b20756e69780a5061636b616765643a20323032302d30352d30362030373a30383a3039205554433b206a65726f656e202d2d2064657465726d696e697374696320736f75726365206d657461646174610a7461696c2062797465732030313233343536373839");
        let mut truncated = stored.clone();
        truncated.truncate(truncated.len() - 5);
        assert!(inflate(&truncated, 1 << 20).is_err());

        let mut bad_nlen = stored.clone();
        bad_nlen[3] ^= 0xFF;
        assert!(inflate(&bad_nlen, 1 << 20).is_err());

        let mut reserved = stored.clone();
        reserved[0] = 0x07; // BFINAL=1 + BTYPE=11
        assert!(inflate(&reserved, 1 << 20).is_err());

        let empty: [u8; 0] = [];
        assert!(inflate(&empty, 1 << 20).is_err());
    }

    /// stored 重编码往返：编码 → 解码恒等；多块（>64KiB）BFINAL 恰落在
    /// 末块；空输入产出单个合法空块。
    #[test]
    fn deflate_stored_roundtrip() {
        let plain = hex(PLAINTEXT_HEX);
        let stream = deflate_stored(&plain);
        assert_eq!(inflate(&stream, 1 << 20).unwrap(), plain);

        let big: Vec<u8> = (0..70_000u32).map(|i| i as u8).collect();
        let stream = deflate_stored(&big);
        assert_eq!(inflate(&stream, 1 << 20).unwrap(), big);

        let empty_stream = deflate_stored(b"");
        assert_eq!(empty_stream, vec![1, 0, 0, 0xFF, 0xFF]);
        assert_eq!(inflate(&empty_stream, 1 << 20).unwrap(), b"");
    }
}
