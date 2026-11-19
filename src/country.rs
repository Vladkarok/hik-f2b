//! The country of an address, from an offline MaxMind DB (`.mmdb`) file
//! such as DB-IP Lite or MaxMind GeoLite2 (`country_db`). Display only: the
//! country never influences whether or when an address is banned.
//!
//! This is a reader for exactly one question, written from the MaxMind DB
//! format specification (<https://maxmind.github.io/MaxMind-DB/>): which
//! two-letter country code does an IPv4 address have.
//!
//! - The file is opened on every lookup, so a replaced file is used without a
//!   restart, and it is never loaded into memory: the metadata is found in
//!   the last 128 KiB, the search tree is walked and the data record decoded
//!   with small positioned reads through one 4 KiB buffer.
//! - The file is untrusted input. Every offset is checked, every loop and
//!   every recursion is bounded, nothing large is allocated, and every
//!   problem is a short error string or "unknown", never a panic.
//! - The only thing taken from a data record is a code of exactly two ASCII
//!   capital letters; anything else is "unknown".

use crate::util;
use std::io::{Read, Seek, SeekFrom};
use std::net::Ipv4Addr;
use std::path::Path;

/// Starts the metadata section; the last one in the file counts.
const MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";
/// The metadata section, marker included, is at most this large.
const MAX_METADATA: u64 = 128 * 1024;
/// Size of the read buffer.
const BLOCK: usize = 4096;
/// Maps and arrays inside maps and arrays (a record has 3 or 4 levels).
const MAX_DEPTH: u32 = 16;
/// Pointers followed in one lookup.
const MAX_POINTERS: u32 = 64;
/// Fields decoded (or skipped) in one lookup. A country record has about a
/// hundred, a city record a few hundred.
const MAX_FIELDS: u32 = 20_000;
/// Largest map or array that is iterated.
const MAX_ENTRIES: u32 = 4096;
/// Entries of the metadata map that are iterated.
const MAX_META_ENTRIES: u32 = 256;
/// Longest map key that is read to be compared.
const MAX_KEY: u32 = 64;
/// Longest `database_type` read, and the length it is shown with.
const MAX_TYPE_READ: u32 = 256;
const MAX_TYPE_SHOWN: usize = 64;
/// Longest error message.
const MAX_ERROR: usize = 150;

/// A two-letter country code: exactly two ASCII capital letters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Code([u8; 2]);

impl Code {
    pub fn parse(bytes: &[u8]) -> Option<Code> {
        match bytes {
            [a, b] if a.is_ascii_uppercase() && b.is_ascii_uppercase() => Some(Code([*a, *b])),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or("??")
    }

    /// The flag emoji: the two letters as regional indicator symbols.
    pub fn flag(&self) -> String {
        self.0
            .iter()
            .map(|b| char::from_u32(0x1f1e6 + u32::from(b.saturating_sub(b'A'))).unwrap_or('?'))
            .collect()
    }
}

impl std::fmt::Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the metadata says about a database (for diagnostics).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Info {
    /// Printable ASCII, at most 64 characters.
    pub database_type: String,
    pub build_epoch: u64,
    pub ip_version: u16,
    pub record_size: u16,
    pub node_count: u32,
}

impl Info {
    /// The build date, `YYYY-MM-DD`.
    pub fn built(&self) -> String {
        // 9999-12-31T23:59:59Z at most, so that the date keeps its shape.
        let epoch = self.build_epoch.min(253_402_300_799);
        util::fmt_ts(i64::try_from(epoch).unwrap_or(0))
            .chars()
            .take(10)
            .collect()
    }

    /// `DBIP-Country-Lite, built 2026-11-01`.
    pub fn describe(&self) -> String {
        format!("{}, built {}", self.database_type, self.built())
    }
}

/// The metadata of the database in `path`.
pub fn info(path: &Path) -> Result<Info, String> {
    info_from(open(path)?)
}

/// The country of `ip` in the database in `path`: `Ok(None)` when the
/// database has no (valid) code for it.
pub fn lookup(path: &Path, ip: Ipv4Addr) -> Result<Option<Code>, String> {
    lookup_from(open(path)?, ip)
}

/// `info` on any seekable reader.
pub fn info_from<R: Read + Seek>(reader: R) -> Result<Info, String> {
    let mut src = Source::new(reader).map_err(clean)?;
    metadata(&mut src).map(|m| m.info).map_err(clean)
}

/// `lookup` on any seekable reader.
pub fn lookup_from<R: Read + Seek>(reader: R, ip: Ipv4Addr) -> Result<Option<Code>, String> {
    let mut src = Source::new(reader).map_err(clean)?;
    find(&mut src, ip).map_err(clean)
}

fn open(path: &Path) -> Result<std::fs::File, String> {
    std::fs::File::open(path)
        .map_err(|e| clean(format!("cannot read {}: {}", path.display(), e.kind())))
}

fn clean(e: String) -> String {
    util::sanitize(&e, MAX_ERROR)
}

fn damaged(what: &str) -> String {
    format!("damaged database: {}", what)
}

fn truncated() -> String {
    damaged("an offset points outside the file or section")
}

/// Positioned reads through one small buffer.
struct Source<R> {
    inner: R,
    len: u64,
    /// File offset of `buf[0]`.
    start: u64,
    buf: Vec<u8>,
}

impl<R: Read + Seek> Source<R> {
    fn new(mut inner: R) -> Result<Source<R>, String> {
        let len = inner
            .seek(SeekFrom::End(0))
            .map_err(|e| format!("read error: {}", e.kind()))?;
        Ok(Source {
            inner,
            len,
            start: 0,
            buf: Vec::new(),
        })
    }

    fn read(&mut self, pos: u64, out: &mut [u8]) -> Result<(), String> {
        let n = u64::try_from(out.len()).map_err(|_| truncated())?;
        let end = pos
            .checked_add(n)
            .filter(|end| *end <= self.len)
            .ok_or_else(truncated)?;
        let cached_end = self
            .start
            .saturating_add(u64::try_from(self.buf.len()).unwrap_or(0));
        if pos >= self.start && end <= cached_end {
            let off = usize::try_from(pos - self.start).map_err(|_| truncated())?;
            let src = off
                .checked_add(out.len())
                .and_then(|stop| self.buf.get(off..stop))
                .ok_or_else(truncated)?;
            out.copy_from_slice(src);
            return Ok(());
        }
        if out.len() > BLOCK {
            return self.read_direct(pos, out);
        }
        let want = usize::try_from((self.len - pos).min(BLOCK as u64)).map_err(|_| truncated())?;
        let mut buf = std::mem::take(&mut self.buf);
        buf.resize(want, 0);
        let result = self.read_direct(pos, &mut buf);
        if let Err(e) = result {
            buf.clear();
            self.buf = buf;
            return Err(e);
        }
        self.start = pos;
        self.buf = buf;
        let src = self.buf.get(..out.len()).ok_or_else(truncated)?;
        out.copy_from_slice(src);
        Ok(())
    }

    fn read_direct(&mut self, pos: u64, out: &mut [u8]) -> Result<(), String> {
        self.inner
            .seek(SeekFrom::Start(pos))
            .and_then(|_| self.inner.read_exact(out))
            .map_err(|e| format!("read error: {}", e.kind()))
    }

    fn byte(&mut self, pos: u64) -> Result<u8, String> {
        let mut b = [0u8; 1];
        self.read(pos, &mut b)?;
        Ok(b[0])
    }

    /// `n` (at most 8) bytes as a big-endian number.
    fn be(&mut self, pos: u64, n: usize) -> Result<u64, String> {
        let mut b = [0u8; 8];
        let part = b.get_mut(..n).ok_or_else(truncated)?;
        self.read(pos, part)?;
        Ok(part.iter().fold(0u64, |acc, x| (acc << 8) | u64::from(*x)))
    }
}

/// The offset (from the end) of the last metadata marker, searched for in
/// the last `MAX_METADATA` bytes, a block at a time from the end.
fn find_marker<R: Read + Seek>(src: &mut Source<R>) -> Result<u64, String> {
    let len = src.len;
    let floor = len.saturating_sub(MAX_METADATA);
    let overlap = (MARKER.len() - 1) as u64;
    let mut end = len;
    let mut chunk = vec![0u8; BLOCK + MARKER.len()];
    while end > floor {
        let begin = end.saturating_sub(BLOCK as u64).max(floor);
        // A marker that starts before `end` may reach past it.
        let stop = end.saturating_add(overlap).min(len);
        let n = usize::try_from(stop - begin).map_err(|_| truncated())?;
        let part = chunk.get_mut(..n).ok_or_else(truncated)?;
        src.read_direct(begin, part)?;
        if let Some(i) = part.windows(MARKER.len()).rposition(|w| w == MARKER) {
            return begin
                .checked_add(u64::try_from(i).map_err(|_| truncated())?)
                .ok_or_else(truncated);
        }
        end = begin;
    }
    Err("not a MaxMind DB file (no metadata marker)".to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// Section-relative target.
    Pointer(u64),
    Str,
    Double,
    Bytes,
    U16,
    U32,
    Map,
    I32,
    U64,
    U128,
    Array,
    Container,
    End,
    Bool,
    Float,
}

#[derive(Clone, Copy, Debug)]
struct Field {
    kind: Kind,
    /// Bytes of payload, entries of a map or array, the value of a boolean.
    size: u32,
    /// File offset of the payload (for a pointer, the byte after it).
    payload: u64,
}

/// Decodes fields in one section (the data section or the metadata), whose
/// pointers are relative to `base` and which ends at `end`. Counts what it
/// does against the per-lookup limits.
struct Decoder<'a, R> {
    src: &'a mut Source<R>,
    base: u64,
    end: u64,
    fields: u32,
    pointers: u32,
}

impl<R: Read + Seek> Decoder<'_, R> {
    fn byte(&mut self, pos: u64) -> Result<u8, String> {
        if pos >= self.end {
            return Err(truncated());
        }
        self.src.byte(pos)
    }

    fn be(&mut self, pos: u64, n: usize) -> Result<u64, String> {
        let stop = pos.checked_add(n as u64).ok_or_else(truncated)?;
        if stop > self.end {
            return Err(truncated());
        }
        self.src.be(pos, n)
    }

    fn after(&self, pos: u64, n: u32) -> Result<u64, String> {
        pos.checked_add(u64::from(n))
            .filter(|p| *p <= self.end)
            .ok_or_else(truncated)
    }

    /// The field at `pos`, without following a pointer.
    fn field(&mut self, pos: u64) -> Result<Field, String> {
        self.fields = self.fields.saturating_add(1);
        if self.fields > MAX_FIELDS {
            return Err(damaged("record too large"));
        }
        let ctrl = self.byte(pos)?;
        let mut p = pos.checked_add(1).ok_or_else(truncated)?;
        let mut t = ctrl >> 5;
        if t == 1 {
            let ss = (ctrl >> 3) & 3;
            let vvv = u64::from(ctrl & 7);
            let (n, add) = match ss {
                0 => (1, 0),
                1 => (2, 2048),
                2 => (3, 526_336),
                _ => (4, 0),
            };
            let raw = self.be(p, n)?;
            let value = if ss == 3 {
                raw
            } else {
                ((vvv << (8 * n)) | raw) + add
            };
            return Ok(Field {
                kind: Kind::Pointer(value),
                size: 0,
                payload: self.after(p, n as u32)?,
            });
        }
        if t == 0 {
            let ext = self.byte(p)?;
            p = self.after(p, 1)?;
            t = match ext {
                1..=8 => 7 + ext,
                _ => return Err(damaged("unknown data type")),
            };
        }
        let low = u32::from(ctrl & 0x1f);
        let size = match low {
            29 => {
                let n = self.be(p, 1)?;
                p = self.after(p, 1)?;
                29 + n
            }
            30 => {
                let n = self.be(p, 2)?;
                p = self.after(p, 2)?;
                285 + n
            }
            31 => {
                let n = self.be(p, 3)?;
                p = self.after(p, 3)?;
                65_821 + n
            }
            n => u64::from(n),
        };
        let size = u32::try_from(size).map_err(|_| truncated())?;
        let kind = match t {
            2 => Kind::Str,
            3 => Kind::Double,
            4 => Kind::Bytes,
            5 => Kind::U16,
            6 => Kind::U32,
            7 => Kind::Map,
            8 => Kind::I32,
            9 => Kind::U64,
            10 => Kind::U128,
            11 => Kind::Array,
            12 => Kind::Container,
            13 => Kind::End,
            14 => Kind::Bool,
            15 => Kind::Float,
            _ => return Err(damaged("unknown data type")),
        };
        Ok(Field {
            kind,
            size,
            payload: p,
        })
    }

    /// The field at `pos`, following a pointer once. A pointer to a pointer
    /// is invalid.
    fn resolve(&mut self, pos: u64) -> Result<Field, String> {
        let f = self.field(pos)?;
        let Kind::Pointer(target) = f.kind else {
            return Ok(f);
        };
        self.pointers = self.pointers.saturating_add(1);
        if self.pointers > MAX_POINTERS {
            return Err(damaged("too many pointers"));
        }
        let at = self
            .base
            .checked_add(target)
            .filter(|p| *p < self.end)
            .ok_or_else(|| damaged("pointer out of range"))?;
        let g = self.field(at)?;
        if matches!(g.kind, Kind::Pointer(_)) {
            return Err(damaged("pointer to a pointer"));
        }
        Ok(g)
    }

    /// The offset after the field at `pos` (a pointer is not followed).
    fn skip(&mut self, pos: u64, depth: u32) -> Result<u64, String> {
        if depth > MAX_DEPTH {
            return Err(damaged("nested too deeply"));
        }
        let f = self.field(pos)?;
        let fixed = |want: u32| {
            if f.size == want {
                Ok(f.size)
            } else {
                Err(damaged("bad size of a number"))
            }
        };
        let most = |max: u32| {
            if f.size <= max {
                Ok(f.size)
            } else {
                Err(damaged("bad size of a number"))
            }
        };
        let bytes = match f.kind {
            Kind::Pointer(_) => return Ok(f.payload),
            Kind::Str | Kind::Bytes => f.size,
            Kind::Double => fixed(8)?,
            Kind::Float => fixed(4)?,
            Kind::U16 => most(2)?,
            Kind::U32 | Kind::I32 => most(4)?,
            Kind::U64 => most(8)?,
            Kind::U128 => most(16)?,
            Kind::Bool => {
                if f.size > 1 {
                    return Err(damaged("bad boolean"));
                }
                0
            }
            Kind::Map | Kind::Array => {
                if f.size > MAX_ENTRIES {
                    return Err(damaged("map or array too large"));
                }
                let per = if f.kind == Kind::Map { 2 } else { 1 };
                let mut p = f.payload;
                for _ in 0..f.size {
                    for _ in 0..per {
                        p = self.skip(p, depth + 1)?;
                    }
                }
                return Ok(p);
            }
            Kind::Container | Kind::End => return Err(damaged("unsupported data type")),
        };
        self.after(f.payload, bytes)
    }

    /// The bytes of a string field of at most `max` bytes; `None` for
    /// anything else.
    fn string(&mut self, f: &Field, max: u32) -> Result<Option<Vec<u8>>, String> {
        if f.kind != Kind::Str || f.size > max {
            return Ok(None);
        }
        let stop = self.after(f.payload, f.size)?;
        let n = usize::try_from(stop - f.payload).map_err(|_| truncated())?;
        let mut out = vec![0u8; n];
        self.src.read(f.payload, &mut out)?;
        Ok(Some(out))
    }

    /// An unsigned number of up to 8 bytes.
    fn uint(&mut self, f: &Field) -> Result<u64, String> {
        let ok = matches!(f.kind, Kind::U16 | Kind::U32 | Kind::U64 | Kind::U128);
        if !ok || f.size > 8 {
            return Err(damaged("metadata number has the wrong type"));
        }
        self.after(f.payload, f.size)?;
        self.be(f.payload, f.size as usize)
    }

    /// The offset of the value of `key` in the map `map`, if it is a map
    /// and has that key.
    fn value_of(&mut self, map: &Field, key: &[u8], depth: u32) -> Result<Option<u64>, String> {
        if map.kind != Kind::Map {
            return Ok(None);
        }
        if map.size > MAX_ENTRIES {
            return Err(damaged("map too large"));
        }
        let mut p = map.payload;
        for _ in 0..map.size {
            let (name, value) = self.key(p)?;
            if name.as_deref() == Some(key) {
                return Ok(Some(value));
            }
            p = self.skip(value, depth + 1)?;
        }
        Ok(None)
    }

    /// The map key at `pos` (`None` when longer than `MAX_KEY`) and the
    /// offset of its value.
    fn key(&mut self, pos: u64) -> Result<(Option<Vec<u8>>, u64), String> {
        let f = self.field(pos)?;
        let (target, next) = match f.kind {
            Kind::Pointer(_) => (self.resolve(pos)?, f.payload),
            _ => (f, self.after(f.payload, f.size)?),
        };
        if target.kind != Kind::Str {
            return Err(damaged("map key is not a string"));
        }
        Ok((self.string(&target, MAX_KEY)?, next))
    }

    /// The code in the string at `pos`, if it is one.
    fn code_at(&mut self, pos: u64) -> Result<Option<Code>, String> {
        let f = self.resolve(pos)?;
        Ok(self.string(&f, 8)?.and_then(|b| Code::parse(&b)))
    }

    /// `country` -> `iso_code` (DB-IP Lite, GeoLite2), else a top-level
    /// `country_code` (IPinfo Lite).
    fn country(&mut self, record: u64) -> Result<Option<Code>, String> {
        let top = self.resolve(record)?;
        if let Some(pos) = self.value_of(&top, b"country", 1)? {
            let country = self.resolve(pos)?;
            if let Some(pos) = self.value_of(&country, b"iso_code", 2)? {
                return self.code_at(pos);
            }
        }
        match self.value_of(&top, b"country_code", 1)? {
            Some(pos) => self.code_at(pos),
            None => Ok(None),
        }
    }
}

struct Meta {
    info: Info,
    data_start: u64,
    data_end: u64,
}

fn metadata<R: Read + Seek>(src: &mut Source<R>) -> Result<Meta, String> {
    let marker = find_marker(src)?;
    let start = marker
        .checked_add(MARKER.len() as u64)
        .ok_or_else(truncated)?;
    let end = src.len;
    let mut d = Decoder {
        src,
        base: start,
        end,
        fields: 0,
        pointers: 0,
    };
    let top = d.resolve(start)?;
    if top.kind != Kind::Map {
        return Err(damaged("metadata is not a map"));
    }
    if top.size > MAX_META_ENTRIES {
        return Err(damaged("metadata too large"));
    }
    let (mut node_count, mut record_size, mut ip_version, mut major) = (None, None, None, None);
    let mut build_epoch = 0;
    let mut database_type = "unknown".to_string();
    let mut p = top.payload;
    for _ in 0..top.size {
        let (name, value) = d.key(p)?;
        let name = name.unwrap_or_default();
        match name.as_slice() {
            b"node_count"
            | b"record_size"
            | b"ip_version"
            | b"binary_format_major_version"
            | b"build_epoch" => {
                let f = d.resolve(value)?;
                let n = d.uint(&f)?;
                match name.as_slice() {
                    b"node_count" => node_count = Some(n),
                    b"record_size" => record_size = Some(n),
                    b"ip_version" => ip_version = Some(n),
                    b"binary_format_major_version" => major = Some(n),
                    _ => build_epoch = n,
                }
            }
            b"database_type" => {
                let f = d.resolve(value)?;
                // Only the start of a long one is read; `skip` below still
                // checks that all of it is in the file.
                let start = Field {
                    size: f.size.min(MAX_TYPE_READ),
                    ..f
                };
                if let Some(text) = d.string(&start, MAX_TYPE_READ)? {
                    database_type = util::sanitize(&String::from_utf8_lossy(&text), MAX_TYPE_SHOWN);
                }
            }
            _ => {}
        }
        p = d.skip(value, 1)?;
    }
    let missing = |what: &str| damaged(&format!("metadata has no {}", what));
    if major.ok_or_else(|| missing("binary_format_major_version"))? != 2 {
        return Err("unsupported MaxMind DB format version".to_string());
    }
    let node_count = node_count.ok_or_else(|| missing("node_count"))?;
    let node_count = u32::try_from(node_count).map_err(|_| damaged("node_count too large"))?;
    let record_size = match record_size.ok_or_else(|| missing("record_size"))? {
        n @ (24 | 28 | 32) => n as u16,
        _ => return Err("unsupported record_size (only 24, 28 and 32 are)".to_string()),
    };
    let ip_version = match ip_version.ok_or_else(|| missing("ip_version"))? {
        n @ (4 | 6) => n as u16,
        _ => return Err(damaged("ip_version is neither 4 nor 6")),
    };
    if node_count == 0 {
        return Err(damaged("empty search tree"));
    }
    let tree = u64::from(node_count)
        .checked_mul(u64::from(record_size / 4))
        .ok_or_else(|| damaged("node_count too large"))?;
    let data_start = tree
        .checked_add(16)
        .filter(|s| *s <= marker)
        .ok_or_else(|| damaged("node_count too large for the file"))?;
    Ok(Meta {
        info: Info {
            database_type,
            build_epoch,
            ip_version,
            record_size,
            node_count,
        },
        data_start,
        data_end: marker,
    })
}

/// One record of a node: `right` for a 1 bit.
fn record<R: Read + Seek>(
    src: &mut Source<R>,
    info: &Info,
    node: u64,
    right: bool,
) -> Result<u64, String> {
    let width = u64::from(info.record_size / 4);
    let at = node.checked_mul(width).ok_or_else(truncated)?;
    let mut b = [0u8; 8];
    let n = usize::try_from(width).map_err(|_| truncated())?;
    let part = b.get_mut(..n).ok_or_else(truncated)?;
    src.read(at, part)?;
    let be = |s: &[u8]| s.iter().fold(0u64, |acc, x| (acc << 8) | u64::from(*x));
    Ok(match (info.record_size, right) {
        (24, false) => be(&b[0..3]),
        (24, true) => be(&b[3..6]),
        (28, false) => (u64::from(b[3] & 0xf0) << 20) | be(&b[0..3]),
        (28, true) => (u64::from(b[3] & 0x0f) << 24) | be(&b[4..7]),
        (_, false) => be(&b[0..4]),
        (_, true) => be(&b[4..8]),
    })
}

fn find<R: Read + Seek>(src: &mut Source<R>, ip: Ipv4Addr) -> Result<Option<Code>, String> {
    let meta = metadata(src)?;
    let info = &meta.info;
    let count = u64::from(info.node_count);
    // An IPv4 address in an IPv6 tree is under ::/96: 96 zero bits first.
    let addr = u128::from(u32::from(ip));
    let bits: u32 = if info.ip_version == 6 { 128 } else { 32 };
    let mut node = 0u64;
    for i in 0..bits {
        let right = (addr >> (bits - 1 - i)) & 1 == 1;
        let value = record(src, info, node, right)?;
        if value < count {
            node = value;
            continue;
        }
        if value == count {
            return Ok(None);
        }
        let offset = value
            .checked_sub(count)
            .and_then(|v| v.checked_sub(16))
            .ok_or_else(|| damaged("bad search tree record"))?;
        let pos = meta
            .data_start
            .checked_add(offset)
            .filter(|p| *p < meta.data_end)
            .ok_or_else(|| damaged("search tree points outside the data"))?;
        let mut d = Decoder {
            src,
            base: meta.data_start,
            end: meta.data_end,
            fields: 0,
            pointers: 0,
        };
        return d.country(pos);
    }
    Err(damaged("search tree is deeper than an address"))
}

#[cfg(test)]
#[path = "../tests/support/mmdb.rs"]
mod mmdb;

#[cfg(test)]
mod tests {
    use super::mmdb::{self, country, ctrl, encode, map, pointer_sized, s, Builder, V};
    use super::*;
    use std::io::Cursor;

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    fn look(db: &[u8], addr: &str) -> Result<Option<String>, String> {
        lookup_from(Cursor::new(db.to_vec()), ip(addr)).map(|c| c.map(|c| c.to_string()))
    }

    fn found(db: &[u8], addr: &str) -> Option<String> {
        look(db, addr).unwrap()
    }

    /// A database whose 198.51.100.0/24 record is `v`.
    fn with_record(v: &V) -> Vec<u8> {
        let mut b = Builder::new(24, 6);
        let off = b.record(v);
        b.net("198.51.100.0/24", off);
        b.build()
    }

    #[test]
    fn every_record_size_and_tree() {
        for record_size in [24, 28, 32] {
            for ip_version in [4, 6] {
                let db = mmdb::simple(record_size, ip_version, "MD");
                let what = format!("{} bit, IPv{}", record_size, ip_version);
                assert_eq!(
                    found(&db, "198.51.100.7").as_deref(),
                    Some("MD"),
                    "{}",
                    what
                );
                assert_eq!(
                    found(&db, "198.51.100.255").as_deref(),
                    Some("MD"),
                    "{}",
                    what
                );
                assert_eq!(found(&db, "203.0.113.9"), None, "{}: empty record", what);
                assert_eq!(found(&db, "192.0.2.1"), None, "{}: not in the tree", what);
                assert_eq!(found(&db, "198.51.101.1"), None, "{}", what);
                let i = info_from(Cursor::new(db)).unwrap();
                assert_eq!(i.database_type, "Test-Country");
                assert_eq!(i.record_size, record_size);
                assert_eq!(i.ip_version, ip_version);
                assert_eq!(i.describe(), "Test-Country, built 2026-11-01");
            }
        }
    }

    #[test]
    fn large_trees_use_the_high_bits_of_28_bit_records() {
        // Enough nodes and data that record values need more than 24 bits.
        let filler = |b: &mut Builder| {
            b.record(&V::Bytes(vec![0u8; 9_000_000]));
            b.record(&V::Bytes(vec![0u8; 9_000_000]));
        };
        let mut b = Builder::new(28, 4);
        filler(&mut b);
        let off = b.record(&country("NL"));
        assert!(off > 1 << 24);
        b.net("198.51.100.0/24", off);
        let off2 = b.record(&country("SE"));
        b.net("198.51.100.128/25", off2);
        let db = b.build();
        assert_eq!(found(&db, "198.51.100.7").as_deref(), Some("NL"));
        assert_eq!(found(&db, "198.51.100.200").as_deref(), Some("SE"));
        let mut b = Builder::new(32, 6);
        filler(&mut b);
        let off = b.record(&country("NO"));
        b.net("203.0.113.0/24", off);
        assert_eq!(found(&b.build(), "203.0.113.1").as_deref(), Some("NO"));
    }

    #[test]
    fn keys_and_values_behind_pointers_of_every_size() {
        for ss in 0..4u8 {
            let mut b = Builder::new(24, 4);
            // Push the shared strings past the offset each size needs.
            let pad = match ss {
                1 => 3000,
                2 => 530_000,
                _ => 0,
            };
            if pad > 0 {
                b.record(&V::Bytes(vec![7u8; pad]));
            }
            let key_country = b.record(&s("country"));
            let key_iso = b.record(&s("iso_code"));
            let code = b.record(&s("MD"));
            let inner = b.record(&V::Map(vec![(
                V::PtrSized(key_iso, ss),
                V::PtrSized(code, ss),
            )]));
            let top = b.record(&V::Map(vec![
                (s("other"), V::PtrSized(code, ss)),
                (V::PtrSized(key_country, ss), V::PtrSized(inner, ss)),
            ]));
            // the tree points at a pointer to the record
            let entry = b.record(&V::PtrSized(top, ss));
            b.net("198.51.100.0/24", entry);
            assert_eq!(
                found(&b.build(), "198.51.100.7").as_deref(),
                Some("MD"),
                "pointer size {}",
                ss
            );
        }
    }

    #[test]
    fn ipinfo_schema() {
        let db = with_record(&map(vec![
            ("asn", s("AS64496")),
            ("country", s("Testland")),
            ("country_code", s("UA")),
            ("continent_code", s("EU")),
        ]));
        assert_eq!(found(&db, "198.51.100.1").as_deref(), Some("UA"));
        // country -> iso_code wins over country_code
        let db = with_record(&map(vec![
            ("country_code", s("UA")),
            ("country", map(vec![("iso_code", s("PL"))])),
        ]));
        assert_eq!(found(&db, "198.51.100.1").as_deref(), Some("PL"));
        // neither
        let db = with_record(&map(vec![("city", map(vec![]))]));
        assert_eq!(found(&db, "198.51.100.1"), None);
        // not a map at all
        assert_eq!(found(&with_record(&s("MD")), "198.51.100.1"), None);
    }

    #[test]
    fn other_fields_before_country_are_skipped() {
        let long = "x".repeat(70_000); // size encoding 31
        let db = with_record(&map(vec![
            (
                "continent",
                map(vec![
                    ("code", s("EU")),
                    ("geoname_id", V::Uint(6, 6255148)),
                    (
                        "names",
                        map(vec![("en", s("Europe")), ("ja", s("ヨーロッパ"))]),
                    ),
                ]),
            ),
            (
                "location",
                map(vec![
                    ("latitude", V::F64(47.0)),
                    ("radius", V::Uint(5, 100)),
                ]),
            ),
            ("float", V::F32(1.5)),
            ("big", V::Uint(10, u128::MAX)),
            ("u64", V::Uint(9, 1 << 40)),
            ("signed", V::I32(-5)),
            ("yes", V::Bool(true)),
            ("no", V::Bool(false)),
            ("blob", V::Bytes(vec![1, 2, 3])),
            ("medium", s(&"y".repeat(300))), // size encoding 30
            ("short", s(&"z".repeat(100))),  // size encoding 29
            ("long", s(&long)),
            (
                "subdivisions",
                V::Array(vec![map(vec![("iso_code", s("CU"))]), V::Array(vec![])]),
            ),
            (
                "country",
                map(vec![
                    ("is_in_european_union", V::Bool(true)),
                    ("iso_code", s("MD")),
                ]),
            ),
        ]));
        assert_eq!(found(&db, "198.51.100.1").as_deref(), Some("MD"));
    }

    #[test]
    fn only_two_capital_letters_are_a_code() {
        for bad in [
            "md",
            "Md",
            "MDA",
            "M",
            "",
            "<b>",
            "M1",
            "\u{41f}\u{41b}",
            "M\n",
            "M\u{0}",
        ] {
            let db = with_record(&country(bad));
            assert_eq!(found(&db, "198.51.100.1"), None, "{:?}", bad);
        }
        let db = with_record(&map(vec![(
            "country",
            map(vec![("iso_code", V::Uint(5, 0x4d44))]),
        )]));
        assert_eq!(found(&db, "198.51.100.1"), None, "a number is not a code");
        let db = with_record(&map(vec![(
            "country",
            map(vec![("iso_code", V::Bytes(b"MD".to_vec()))]),
        )]));
        assert_eq!(found(&db, "198.51.100.1"), None, "bytes are not a code");
        assert_eq!(Code::parse(b"MD").unwrap().flag(), "\u{1f1f2}\u{1f1e9}");
        assert_eq!(Code::parse(b"AZ").unwrap().flag(), "\u{1f1e6}\u{1f1ff}");
    }

    #[test]
    fn broken_files_are_errors() {
        let good = mmdb::simple(24, 6, "MD");
        let err = |db: &[u8]| look(db, "198.51.100.1").unwrap_err();
        assert!(err(b"").contains("no metadata marker"));
        assert!(err(&vec![0u8; 300_000]).contains("no metadata marker"));
        // truncated at the end: inside the metadata
        assert!(err(&good[..good.len() - 3]).contains("damaged"));
        // truncated in the tree: the metadata is gone
        assert!(err(&good[..100]).contains("no metadata marker"));
        // the marker more than 128 KiB before the end is not found
        let mut far = good.clone();
        far.extend(vec![0u8; 140_000]);
        assert!(err(&far).contains("no metadata marker"));

        let meta = |key: &str, v: V| {
            let mut b = Builder::new(24, 6);
            let off = b.record(&country("MD"));
            b.net("198.51.100.0/24", off);
            b.meta.push((key.to_string(), v));
            b.build()
        };
        assert!(err(&meta("node_count", V::Uint(6, u128::from(u32::MAX)))).contains("node_count"));
        assert!(err(&meta("node_count", V::Uint(9, 1 << 40))).contains("node_count"));
        assert!(err(&meta("node_count", V::Uint(6, 0))).contains("empty"));
        assert!(err(&meta("node_count", s("many"))).contains("wrong type"));
        assert!(err(&meta("record_size", V::Uint(5, 20))).contains("record_size"));
        assert!(err(&meta("record_size", V::Uint(5, 33))).contains("record_size"));
        assert!(err(&meta("record_size", V::Uint(9, u128::from(u64::MAX)))).contains("record_size"));
        assert!(err(&meta("ip_version", V::Uint(5, 5))).contains("ip_version"));
        assert!(err(&meta("binary_format_major_version", V::Uint(5, 3))).contains("version"));
        // a smaller node_count than the tree has: records point "into the data"
        let r = look(&meta("node_count", V::Uint(6, 3)), "198.51.100.1");
        assert!(r.is_err() || r == Ok(None), "{:?}", r);

        // a marker in the data section: the last one counts
        let mut b = Builder::new(24, 6);
        b.record(&V::Bytes(mmdb::MARKER.to_vec()));
        let off = b.record(&country("MD"));
        b.net("198.51.100.0/24", off);
        assert_eq!(found(&b.build(), "198.51.100.1").as_deref(), Some("MD"));

        // metadata that is not a map, or has no node_count
        let mut b = Builder::new(24, 6);
        b.meta_raw = Some({
            let mut m = Vec::new();
            encode(&s("hello"), &mut m);
            m
        });
        assert!(err(&b.build()).contains("not a map"));
        b.meta_raw = Some({
            let mut m = Vec::new();
            encode(
                &map(vec![("binary_format_major_version", V::Uint(5, 2))]),
                &mut m,
            );
            m
        });
        assert!(err(&b.build()).contains("no node_count"));
    }

    #[test]
    fn metadata_behind_pointers() {
        let mut b = Builder::new(24, 4);
        let off = b.record(&country("MD"));
        b.net("198.51.100.0/24", off);
        let (_, count) = b.tree();
        // The metadata section: a pointer (2 bytes) to the map, the strings
        // the map points to, then the map. Pointers here are relative to
        // the start of the metadata.
        let mut strings = Vec::new();
        encode(&s("database_type"), &mut strings);
        let name = 2 + strings.len() as u32;
        encode(&s("Pointed-Country"), &mut strings);
        let map_at = 2 + strings.len() as u32;
        let mut m = Vec::new();
        ctrl(&mut m, 7, 6);
        for (k, v) in [
            ("node_count", V::Uint(6, u128::from(count))),
            ("record_size", V::Uint(5, 24)),
            ("ip_version", V::Uint(5, 4)),
            ("binary_format_major_version", V::Uint(5, 2)),
            ("build_epoch", V::Uint(9, 0)),
        ] {
            encode(&s(k), &mut m);
            encode(&v, &mut m);
        }
        pointer_sized(&mut m, 2, 0);
        pointer_sized(&mut m, name, 0);
        let mut raw = Vec::new();
        pointer_sized(&mut raw, map_at, 0);
        raw.extend(strings);
        raw.extend(m);
        b.meta_raw = Some(raw);
        let db = b.build();
        let i = info_from(Cursor::new(db.clone())).unwrap();
        assert_eq!(i.database_type, "Pointed-Country");
        assert_eq!(i.describe(), "Pointed-Country, built 1970-01-01");
        assert_eq!(found(&db, "198.51.100.1").as_deref(), Some("MD"));
    }

    #[test]
    fn hostile_data_records() {
        let err = |v: &V| look(&with_record(v), "198.51.100.1").unwrap_err();
        // a pointer to itself, and a pointer to a pointer
        let mut b = Builder::new(24, 6);
        b.data.extend([0x20, 0x00]); // offset 0: pointer to offset 0
        b.net("198.51.100.0/24", 0);
        assert!(look(&b.build(), "198.51.100.1")
            .unwrap_err()
            .contains("pointer to a pointer"));
        let mut b = Builder::new(24, 6);
        b.data.extend([0x20, 0x02, 0x20, 0x00]); // 0 -> 2 -> 0
        b.net("198.51.100.0/24", 0);
        assert!(look(&b.build(), "198.51.100.1")
            .unwrap_err()
            .contains("pointer to a pointer"));
        // a value pointing back at the record it is in: never followed
        let mut b = Builder::new(24, 6);
        let mut rec = Vec::new();
        ctrl(&mut rec, 7, 2);
        encode(&s("self"), &mut rec);
        pointer_sized(&mut rec, 0, 0);
        encode(&s("country"), &mut rec);
        pointer_sized(&mut rec, 0, 0);
        b.data.extend(rec);
        b.net("198.51.100.0/24", 0);
        assert_eq!(found(&b.build(), "198.51.100.1"), None);
        // a pointer beyond the data section
        assert!(err(&map(vec![("country", V::PtrSized(0xffff_fff0, 3))])).contains("out of range"));
        // deep nesting before the country
        let mut deep = V::Array(vec![]);
        for _ in 0..40 {
            deep = V::Array(vec![deep]);
        }
        assert!(err(&map(vec![("deep", deep), ("country", country("MD"))])).contains("deeply"));
        // a map claiming far more entries than there are bytes
        let mut huge = Vec::new();
        ctrl(&mut huge, 7, 16_000_000);
        assert!(err(&V::Raw(huge)).contains("too large"));
        let mut many = Vec::new();
        ctrl(&mut many, 11, 4000);
        many.extend([0x00; 2]); // an invalid type, then nothing
        assert!(
            err(&map(vec![("a", V::Raw(many)), ("country", country("MD"))])).contains("damaged")
        );
        // a string longer than the file
        let mut long = Vec::new();
        ctrl(&mut long, 2, 16_000_000);
        assert!(
            err(&map(vec![("a", V::Raw(long)), ("country", country("MD"))])).contains("outside")
        );
        // keys that are not strings
        assert!(err(&V::Map(vec![(V::Uint(5, 1), country("MD"))])).contains("key"));
        // unknown and unsupported types, bad sizes
        let raw = |bytes: &[u8]| {
            map(vec![
                ("a", V::Raw(bytes.to_vec())),
                ("country", country("MD")),
            ])
        };
        assert!(err(&raw(&[0x00, 0x09])).contains("unknown data type"));
        assert!(err(&raw(&[0x00, 0x00])).contains("unknown data type"));
        assert!(err(&raw(&[0x00, 0x05])).contains("unsupported"));
        assert!(err(&raw(&[0x00, 0x06])).contains("unsupported"));
        assert!(err(&raw(&[0x02, 0x07])).contains("boolean"));
        assert!(err(&raw(&[0x64, 0, 0, 0])).contains("number")); // double of 4 bytes
        assert!(err(&raw(&[0xa3, 0, 0, 0])).contains("number")); // u16 of 3 bytes
                                                                 // a field budget: thousands of tiny fields
        let mut pairs: Vec<(&str, V)> = (0..6)
            .map(|_| ("w", V::Array((0..4000).map(|_| V::Bool(true)).collect())))
            .collect();
        pairs.push(("country", country("MD")));
        assert!(err(&map(pairs)).contains("too large"));
    }

    #[test]
    fn mutated_files_never_panic() {
        let mut b = Builder::new(28, 6);
        let shared = b.record(&s("iso_code"));
        let rec = b.record(&V::Map(vec![
            (
                s("continent"),
                map(vec![
                    ("code", s("EU")),
                    ("names", map(vec![("en", s("Europe"))])),
                ]),
            ),
            (
                s("location"),
                map(vec![("lat", V::F64(1.0)), ("acc", V::Uint(5, 5))]),
            ),
            (
                s("flags"),
                V::Array(vec![V::Bool(true), V::I32(-1), V::F32(2.0), V::Uint(10, 7)]),
            ),
            (s("country"), V::Map(vec![(V::Ptr(shared), s("MD"))])),
        ]));
        b.net("198.51.100.0/24", rec);
        b.net("203.0.113.0/25", rec);
        let good = b.build();
        assert_eq!(found(&good, "198.51.100.1").as_deref(), Some("MD"));

        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let addrs = [ip("198.51.100.1"), ip("203.0.113.5"), ip("192.0.2.1")];
        for _ in 0..3000 {
            let mut db = good.clone();
            for _ in 0..1 + next() % 4 {
                let len = db.len() as u64;
                let at = (next() % len) as usize;
                match next() % 6 {
                    0 => db[at] = next() as u8,
                    1 => db[at] ^= 1 << (next() % 8),
                    2 => db[at] = [0x20, 0x38, 0xe0, 0x1f, 0xff, 0x00][(next() % 6) as usize],
                    3 => db.truncate(at),
                    4 => {
                        let end = (at + 8).min(db.len());
                        db[at..end].fill(0xff);
                    }
                    _ => db.insert(at, next() as u8),
                }
                if db.is_empty() {
                    break;
                }
            }
            let _ = info_from(Cursor::new(db.clone()));
            for a in addrs {
                if let Ok(Some(code)) = lookup_from(Cursor::new(db.clone()), a) {
                    assert!(code.as_str().bytes().all(|b| b.is_ascii_uppercase()));
                }
            }
        }
    }

    #[test]
    fn errors_are_short_and_name_no_contents() {
        let missing = lookup(
            Path::new("/nonexistent/hik-f2b-country.mmdb"),
            ip("192.0.2.1"),
        );
        let e = missing.unwrap_err();
        assert!(
            e.starts_with("cannot read /nonexistent/hik-f2b-country.mmdb: "),
            "{}",
            e
        );
        assert!(info(Path::new("/nonexistent/x.mmdb")).is_err());
        let mut b = Builder::new(24, 4);
        b.database_type = format!("Evil\n\u{1b}[2J<b>{}", "x".repeat(500));
        let i = info_from(Cursor::new(b.build())).unwrap();
        assert!(
            i.database_type.starts_with("Evil??[2J<b>x"),
            "{}",
            i.database_type
        );
        assert_eq!(i.database_type.len(), MAX_TYPE_SHOWN);
        assert_eq!(
            Info {
                build_epoch: u64::MAX,
                ..i
            }
            .built(),
            "9999-12-31"
        );
    }
}
