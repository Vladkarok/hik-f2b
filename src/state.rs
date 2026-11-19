//! Persistent state: where each NVR log was read up to, failure counters,
//! bans that still have to be applied and the ban rate limit. A plain
//! line-based text file; anything that does not parse or is out of range is
//! ignored, so a damaged or hand-edited file can never make the daemon do
//! arithmetic on absurd values.

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;

/// Version 2 changed the meaning of the failure times (host time instead of
/// device time); files of other versions are ignored and the daemon starts
/// fresh.
const HEADER: &str = "hik-f2b-state 2";
const MAX_FILE: u64 = 16 * 1024 * 1024;

/// Upper bound on addresses with a running failure counter.
pub const MAX_TRACKED: usize = 10_000;
/// Upper bound on bans waiting to be applied.
pub const MAX_PENDING: usize = 1000;
/// Upper bound on remembered log entries per NVR.
pub const MAX_SEEN: usize = 50_000;
/// Failure times kept per address (the engine keeps fewer).
const MAX_TIMES: usize = 4096;
const MAX_BANNED: usize = 100_000;
const MAX_RATE: usize = 10_000;
/// 9999-12-31T23:59:59Z: anything later is not a time.
pub const MAX_TIME: i64 = 253_402_300_799;

#[derive(Default, Clone, Debug, PartialEq)]
pub struct NvrState {
    /// Device time up to which the log has been read.
    pub since: i64,
    /// Device clock minus host clock at the last successful read, used to
    /// notice the device clock jumping.
    pub offset: Option<i64>,
    /// Entries seen in the last (overlapping) query window, by key hash.
    pub seen: HashMap<String, u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Pending {
    /// Host time of the failure that reached the threshold.
    pub ts: i64,
    pub count: usize,
    pub nvr: String,
    /// Already sanitised to printable ASCII.
    pub user: String,
}

#[derive(Default, Debug, PartialEq)]
pub struct State {
    pub nvr: BTreeMap<String, NvrState>,
    /// Host times of recent failures per address.
    pub fails: BTreeMap<Ipv4Addr, Vec<i64>>,
    /// Host time until which an address counts as handled (banned, or
    /// reported in notify-only mode).
    pub banned: BTreeMap<Ipv4Addr, u64>,
    pub pending: BTreeMap<Ipv4Addr, Pending>,
    /// Host times of the bans applied in the last hour (the rate limit).
    pub recent_bans: Vec<u64>,
}

fn time(text: &str) -> Option<i64> {
    text.parse::<i64>()
        .ok()
        .filter(|t| (0..=MAX_TIME).contains(t))
}

fn utime(text: &str) -> Option<u64> {
    time(text).map(|t| t as u64)
}

/// An NVR name as the configuration allows it.
fn name_ok(text: &str) -> bool {
    crate::util::is_name(text, 32)
}

fn key_ok(text: &str) -> bool {
    text.len() == 32 && text.chars().all(|c| c.is_ascii_hexdigit())
}

impl State {
    pub fn serialize(&self) -> String {
        let mut out = format!("{}\n", HEADER);
        for (name, st) in &self.nvr {
            let offset = st
                .offset
                .map(|o| o.to_string())
                .unwrap_or_else(|| "-".to_string());
            out.push_str(&format!("nvr {} {} {}\n", name, st.since, offset));
            let mut seen: Vec<_> = st.seen.iter().collect();
            seen.sort();
            for (key, count) in seen {
                out.push_str(&format!("seen {} {} {}\n", name, key, count));
            }
        }
        for (ip, times) in &self.fails {
            for t in times {
                out.push_str(&format!("fail {} {}\n", ip, t));
            }
        }
        for (ip, until) in &self.banned {
            out.push_str(&format!("ban {} {}\n", ip, until));
        }
        for (ip, p) in &self.pending {
            out.push_str(&format!(
                "pending {} {} {} {} {}\n",
                ip, p.ts, p.count, p.nvr, p.user
            ));
        }
        for t in &self.recent_bans {
            out.push_str(&format!("rate {}\n", t));
        }
        out
    }

    pub fn parse(text: &str) -> State {
        let mut st = State::default();
        let mut lines = text.lines();
        if lines.next().map(str::trim) != Some(HEADER) {
            return st;
        }
        // An NVR is known only through a valid `nvr` line: `seen` lines alone
        // must not fake a read position of 0.
        let mut positioned = std::collections::HashSet::new();
        for line in lines {
            let f: Vec<&str> = line.split(' ').collect();
            match f.as_slice() {
                ["nvr", name, since, offset] if name_ok(name) => {
                    let offset = match *offset {
                        "-" => Some(None),
                        o => o
                            .parse::<i64>()
                            .ok()
                            .filter(|o| o.abs() <= MAX_TIME)
                            .map(Some),
                    };
                    if let (Some(since), Some(offset)) = (time(since), offset) {
                        let nvr = st.nvr.entry(name.to_string()).or_default();
                        nvr.since = since;
                        nvr.offset = offset;
                        positioned.insert(name.to_string());
                    }
                }
                ["seen", name, key, count] if name_ok(name) && key_ok(key) => {
                    if let Some(count) = count.parse::<u32>().ok().filter(|c| *c <= 1_000_000) {
                        let nvr = st.nvr.entry(name.to_string()).or_default();
                        if nvr.seen.len() < MAX_SEEN {
                            nvr.seen.insert(key.to_string(), count);
                        }
                    }
                }
                ["fail", ip, t] => {
                    if let (Ok(ip), Some(t)) = (ip.parse::<Ipv4Addr>(), time(t)) {
                        if st.fails.len() < MAX_TRACKED || st.fails.contains_key(&ip) {
                            let times = st.fails.entry(ip).or_default();
                            if times.len() < MAX_TIMES {
                                times.push(t);
                            }
                        }
                    }
                }
                ["ban", ip, until] => {
                    if let (Ok(ip), Some(until)) = (ip.parse::<Ipv4Addr>(), utime(until)) {
                        if st.banned.len() < MAX_BANNED {
                            st.banned.insert(ip, until);
                        }
                    }
                }
                ["pending", ip, ts, count, nvr, user @ ..] if name_ok(nvr) => {
                    let count = count
                        .parse::<usize>()
                        .ok()
                        .filter(|c| (1..=1_000_000).contains(c));
                    if let (Ok(ip), Some(ts), Some(count)) =
                        (ip.parse::<Ipv4Addr>(), time(ts), count)
                    {
                        if st.pending.len() < MAX_PENDING {
                            st.pending.insert(
                                ip,
                                Pending {
                                    ts,
                                    count,
                                    nvr: nvr.to_string(),
                                    user: crate::util::sanitize(&user.join(" "), 64),
                                },
                            );
                        }
                    }
                }
                ["rate", t] => {
                    if let Some(t) = utime(t) {
                        if st.recent_bans.len() < MAX_RATE {
                            st.recent_bans.push(t);
                        }
                    }
                }
                _ => {}
            }
        }
        st.nvr.retain(|name, _| positioned.contains(name));
        for times in st.fails.values_mut() {
            times.sort_unstable();
        }
        st
    }

    pub fn load(path: &Path) -> State {
        match std::fs::metadata(path) {
            Ok(m) if m.len() <= MAX_FILE => {}
            _ => return State::default(),
        }
        std::fs::read_to_string(path)
            .map(|text| State::parse(&text))
            .unwrap_or_default()
    }

    /// Writes the file atomically, readable by the owner only.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(self.serialize().as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn round_trip() {
        let mut st = State::default();
        let nvr = st.nvr.entry("nvr1".to_string()).or_default();
        nvr.since = 1_700_000_000;
        nvr.offset = Some(-7200);
        nvr.seen.insert(KEY.to_string(), 2);
        st.nvr.entry("nvr2".to_string()).or_default().since = 5;
        let ip: Ipv4Addr = "198.51.100.7".parse().unwrap();
        st.fails.insert(ip, vec![10, 20]);
        st.banned.insert("203.0.113.5".parse().unwrap(), 99);
        st.pending.insert(
            ip,
            Pending {
                ts: 30,
                count: 5,
                nvr: "nvr1".to_string(),
                user: "illegal usernam".to_string(),
            },
        );
        st.recent_bans = vec![1_700_000_100, 1_700_000_200];
        assert_eq!(State::parse(&st.serialize()), st);
    }

    #[test]
    fn garbage_is_ignored() {
        assert_eq!(
            State::parse("something else\nfail 1.2.3.4 5\n"),
            State::default()
        );
        // version 1 files are not read: their failure times were device time
        assert_eq!(
            State::parse("hik-f2b-state 1\nfail 198.51.100.7 5\nnvr a 5\n"),
            State::default()
        );
        let st = State::parse(
            "hik-f2b-state 2\nfail not-an-ip 5\nban 1.2.3.4 x\nwhatever\nfail 198.51.100.7 5\n",
        );
        assert_eq!(st.fails.len(), 1);
        assert!(st.banned.is_empty());
    }

    #[test]
    fn absurd_values_are_rejected() {
        let st = State::parse(&format!(
            "hik-f2b-state 2\n\
             nvr a -5 0\nnvr b 99999999999999999 0\nnvr c 5 99999999999999999\nnvr d/x 5 0\n\
             nvr e 5 -7200\n\
             seen e {k} -1\nseen e {k} 99999999999\nseen e short 1\n\
             fail 198.51.100.7 -1\nfail 198.51.100.8 9223372036854775807\n\
             ban 198.51.100.9 -1\nban 198.51.100.10 18446744073709551615\n\
             pending 198.51.100.11 -5 5 e u\npending 198.51.100.12 5 0 e u\n\
             pending 198.51.100.13 5 5 ../x u\n\
             rate -1\nrate 99999999999999999\n",
            k = KEY
        ));
        assert_eq!(st.nvr.keys().collect::<Vec<_>>(), vec!["e"]);
        assert_eq!(st.nvr["e"].offset, Some(-7200));
        assert!(st.nvr["e"].seen.is_empty());
        assert!(st.fails.is_empty());
        assert!(st.banned.is_empty());
        assert!(st.pending.is_empty());
        assert!(st.recent_bans.is_empty());
    }
}
