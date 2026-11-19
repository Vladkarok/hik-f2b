//! A small MaxMind DB writer for tests: builds synthetic databases with
//! IPv4 networks, in IPv4 or IPv6 trees, with any record size the reader
//! supports. It writes what the tests tell it to, including broken files.
//!
//! Shared by the unit tests of `src/country.rs` and by `tests/e2e.rs`.

#![allow(dead_code)]

pub const MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";

/// A value of the MaxMind DB data format.
pub enum V {
    Str(Vec<u8>),
    /// Keys are normally `Str`, but may be anything (pointers, or broken).
    Map(Vec<(V, V)>),
    Array(Vec<V>),
    /// (type number 5, 6, 9 or 10, value)
    Uint(u8, u128),
    I32(i32),
    F64(f64),
    F32(f32),
    Bool(bool),
    Bytes(Vec<u8>),
    /// A pointer of the smallest size that holds the offset.
    Ptr(u32),
    /// A pointer of the given size code (0 to 3).
    PtrSized(u32, u8),
    /// Bytes written as they are.
    Raw(Vec<u8>),
}

pub fn s(text: &str) -> V {
    V::Str(text.as_bytes().to_vec())
}

pub fn map(pairs: Vec<(&str, V)>) -> V {
    V::Map(pairs.into_iter().map(|(k, v)| (s(k), v)).collect())
}

/// `{"country": {"iso_code": code, "names": {"en": name}}}`, the shape of
/// DB-IP Lite and GeoLite2 records.
pub fn country(code: &str) -> V {
    map(vec![(
        "country",
        map(vec![
            ("geoname_id", V::Uint(6, 617790)),
            ("iso_code", s(code)),
            (
                "names",
                map(vec![("en", s("Testland")), ("de", s("Testland"))]),
            ),
        ]),
    )])
}

/// A control byte (and extended type byte and size bytes).
pub fn ctrl(out: &mut Vec<u8>, t: u8, size: usize) {
    let (low, ext): (u8, Vec<u8>) = if size < 29 {
        (size as u8, vec![])
    } else if size < 285 {
        (29, vec![(size - 29) as u8])
    } else if size < 65821 {
        let n = size - 285;
        (30, vec![(n >> 8) as u8, n as u8])
    } else {
        let n = size - 65821;
        (31, vec![(n >> 16) as u8, (n >> 8) as u8, n as u8])
    };
    if t <= 7 {
        out.push((t << 5) | low);
    } else {
        out.push(low);
        out.push(t - 7);
    }
    out.extend(ext);
}

pub fn pointer_sized(out: &mut Vec<u8>, value: u32, ss: u8) {
    match ss {
        0 => {
            assert!(value < 2048);
            out.push(0x20 | ((value >> 8) as u8 & 7));
            out.push(value as u8);
        }
        1 => {
            let v = value.checked_sub(2048).expect("size 1 pointer below 2048");
            assert!(v < 1 << 19);
            out.push(0x28 | ((v >> 16) as u8 & 7));
            out.extend([(v >> 8) as u8, v as u8]);
        }
        2 => {
            let v = value
                .checked_sub(526336)
                .expect("size 2 pointer below 526336");
            assert!(v < 1 << 27);
            out.push(0x30 | ((v >> 24) as u8 & 7));
            out.extend([(v >> 16) as u8, (v >> 8) as u8, v as u8]);
        }
        _ => {
            out.push(0x38);
            out.extend(value.to_be_bytes());
        }
    }
}

pub fn pointer(out: &mut Vec<u8>, value: u32) {
    let ss = if value < 2048 {
        0
    } else if value < 2048 + (1 << 19) {
        1
    } else if value < 526336 + (1 << 27) {
        2
    } else {
        3
    };
    pointer_sized(out, value, ss);
}

fn uint_bytes(value: u128) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    bytes[skip..].to_vec()
}

pub fn encode(v: &V, out: &mut Vec<u8>) {
    match v {
        V::Str(b) => {
            ctrl(out, 2, b.len());
            out.extend(b);
        }
        V::Map(pairs) => {
            ctrl(out, 7, pairs.len());
            for (k, v) in pairs {
                encode(k, out);
                encode(v, out);
            }
        }
        V::Array(items) => {
            ctrl(out, 11, items.len());
            for item in items {
                encode(item, out);
            }
        }
        V::Uint(t, n) => {
            let b = uint_bytes(*n);
            ctrl(out, *t, b.len());
            out.extend(b);
        }
        V::I32(n) => {
            ctrl(out, 8, 4);
            out.extend(n.to_be_bytes());
        }
        V::F64(x) => {
            ctrl(out, 3, 8);
            out.extend(x.to_be_bytes());
        }
        V::F32(x) => {
            ctrl(out, 15, 4);
            out.extend(x.to_be_bytes());
        }
        V::Bool(b) => ctrl(out, 14, usize::from(*b)),
        V::Bytes(b) => {
            ctrl(out, 4, b.len());
            out.extend(b);
        }
        V::Ptr(n) => pointer(out, *n),
        V::PtrSized(n, ss) => pointer_sized(out, *n, *ss),
        V::Raw(b) => out.extend(b),
    }
}

#[derive(Clone, Copy)]
enum Rec {
    Empty,
    Node(usize),
    Data(u32),
}

pub struct Builder {
    pub record_size: u16,
    pub ip_version: u16,
    /// The data section; `record` appends to it.
    pub data: Vec<u8>,
    nets: Vec<(u32, u8, u32)>,
    /// Metadata keys that replace the default ones or are added.
    pub meta: Vec<(String, V)>,
    /// Replaces the whole metadata section (after the marker).
    pub meta_raw: Option<Vec<u8>>,
    pub database_type: String,
}

impl Builder {
    pub fn new(record_size: u16, ip_version: u16) -> Builder {
        Builder {
            record_size,
            ip_version,
            data: Vec::new(),
            nets: Vec::new(),
            meta: Vec::new(),
            meta_raw: None,
            database_type: "Test-Country".to_string(),
        }
    }

    /// Appends a value to the data section and returns its offset.
    pub fn record(&mut self, v: &V) -> u32 {
        let off = self.data.len() as u32;
        encode(v, &mut self.data);
        off
    }

    /// Maps an IPv4 network (`a.b.c.d/len`, len 1 to 32) to a data offset.
    pub fn net(&mut self, cidr: &str, off: u32) {
        let (addr, len) = cidr.split_once('/').unwrap();
        let addr: std::net::Ipv4Addr = addr.parse().unwrap();
        let len: u8 = len.parse().unwrap();
        assert!((1..=32).contains(&len));
        self.nets.push((u32::from(addr), len, off));
    }

    /// The search tree and its node count.
    pub fn tree(&self) -> (Vec<u8>, u32) {
        let mut nodes: Vec<[Rec; 2]> = vec![[Rec::Empty, Rec::Empty]];
        let lead: u32 = if self.ip_version == 6 { 96 } else { 0 };
        for &(addr, len, off) in &self.nets {
            let depth = lead + u32::from(len);
            let bit = |i: u32| -> usize {
                if i < lead {
                    0
                } else {
                    ((addr >> (31 - (i - lead))) & 1) as usize
                }
            };
            let mut cur = 0;
            for i in 0..depth - 1 {
                let b = bit(i);
                cur = match nodes[cur][b] {
                    Rec::Node(n) => n,
                    old => {
                        let fill = match old {
                            Rec::Data(_) => old,
                            _ => Rec::Empty,
                        };
                        nodes.push([fill, fill]);
                        let n = nodes.len() - 1;
                        nodes[cur][b] = Rec::Node(n);
                        n
                    }
                };
            }
            nodes[cur][bit(depth - 1)] = Rec::Data(off);
        }
        let count = nodes.len() as u32;
        let value = |r: Rec| -> u32 {
            match r {
                Rec::Empty => count,
                Rec::Node(n) => n as u32,
                Rec::Data(off) => count + 16 + off,
            }
        };
        let mut out = Vec::new();
        for [l, r] in nodes {
            let (l, r) = (value(l), value(r));
            match self.record_size {
                24 => {
                    out.extend(&l.to_be_bytes()[1..]);
                    out.extend(&r.to_be_bytes()[1..]);
                }
                28 => {
                    out.extend(&l.to_be_bytes()[1..]);
                    out.push((((l >> 24) & 0xf) << 4) as u8 | ((r >> 24) & 0xf) as u8);
                    out.extend(&r.to_be_bytes()[1..]);
                }
                _ => {
                    out.extend(l.to_be_bytes());
                    out.extend(r.to_be_bytes());
                }
            }
        }
        (out, count)
    }

    pub fn build(&self) -> Vec<u8> {
        let (tree, count) = self.tree();
        let mut out = tree;
        out.extend([0u8; 16]);
        out.extend(&self.data);
        out.extend(MARKER);
        match &self.meta_raw {
            Some(raw) => out.extend(raw),
            None => {
                let mut pairs: Vec<(String, V)> = vec![
                    ("node_count".to_string(), V::Uint(6, u128::from(count))),
                    (
                        "record_size".to_string(),
                        V::Uint(5, u128::from(self.record_size)),
                    ),
                    (
                        "ip_version".to_string(),
                        V::Uint(5, u128::from(self.ip_version)),
                    ),
                    ("database_type".to_string(), s(&self.database_type)),
                    ("languages".to_string(), V::Array(vec![s("en"), s("de")])),
                    ("binary_format_major_version".to_string(), V::Uint(5, 2)),
                    ("binary_format_minor_version".to_string(), V::Uint(5, 0)),
                    // 2026-11-01T00:00:00Z
                    ("build_epoch".to_string(), V::Uint(9, 1_793_491_200)),
                    ("description".to_string(), map(vec![("en", s("test data"))])),
                ];
                for (key, value) in &self.meta {
                    pairs.retain(|(k, _)| k != key);
                    pairs.push((key.clone(), clone(value)));
                }
                let mut meta = Vec::new();
                ctrl(&mut meta, 7, pairs.len());
                for (k, v) in &pairs {
                    encode(&s(k), &mut meta);
                    encode(v, &mut meta);
                }
                out.extend(meta);
            }
        }
        out
    }
}

fn clone(v: &V) -> V {
    match v {
        V::Str(b) => V::Str(b.clone()),
        V::Map(p) => V::Map(p.iter().map(|(k, v)| (clone(k), clone(v))).collect()),
        V::Array(a) => V::Array(a.iter().map(clone).collect()),
        V::Uint(t, n) => V::Uint(*t, *n),
        V::I32(n) => V::I32(*n),
        V::F64(x) => V::F64(*x),
        V::F32(x) => V::F32(*x),
        V::Bool(b) => V::Bool(*b),
        V::Bytes(b) => V::Bytes(b.clone()),
        V::Ptr(n) => V::Ptr(*n),
        V::PtrSized(n, ss) => V::PtrSized(*n, *ss),
        V::Raw(b) => V::Raw(b.clone()),
    }
}

/// A database where 198.51.100.0/24 has country `code` and 203.0.113.0/24
/// has none of its own (an empty record), in the given tree layout.
pub fn simple(record_size: u16, ip_version: u16, code: &str) -> Vec<u8> {
    let mut b = Builder::new(record_size, ip_version);
    let off = b.record(&country(code));
    b.net("198.51.100.0/24", off);
    let empty = b.record(&map(vec![]));
    b.net("203.0.113.0/24", empty);
    b.build()
}
