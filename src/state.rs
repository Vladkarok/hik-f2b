//! Persistent state: where each NVR log was read up to, failure counters,
//! bans that still have to be applied and the ban rate limit. A plain
//! line-based text file; anything that does not parse or is out of range is
//! ignored, so a damaged or hand-edited file can never make the daemon do
//! arithmetic on absurd values.
//!
//! A file that cannot be used at all (too large, unreadable, not text, of
//! another version) is not silently replaced: `load` says why at WARNING
//! level and moves it aside, since it may hold the only record of who is
//! banned. The file is written and read line by line, so neither needs a
//! copy of it in memory.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hasher;
use std::io::{BufRead, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

/// Version 2 changed the meaning of the failure times (host time instead of
/// device time); files of other versions are not used.
const HEADER: &str = "hik-f2b-state 2";
pub const MAX_FILE: u64 = 16 * 1024 * 1024;

/// Upper bound on addresses with a running failure counter.
pub const MAX_TRACKED: usize = 10_000;
/// Upper bound on the failure times of all addresses together. With
/// `maxretry` above 5 the engine keeps more times per address (see
/// `engine::register`) and so tracks fewer addresses.
pub const MAX_FAIL_TIMES: usize = 200_000;
/// Upper bound on bans waiting to be applied.
pub const MAX_PENDING: usize = 1000;
/// Upper bound on remembered log entries per NVR.
pub const MAX_SEEN: usize = 50_000;
/// Failure times kept per address (the engine keeps fewer).
const MAX_TIMES: usize = 4096;
/// Upper bound on banned (or reported) addresses remembered.
pub const MAX_BANNED: usize = 100_000;
const MAX_RATE: usize = 10_000;
/// 9999-12-31T23:59:59Z: anything later is not a time.
pub const MAX_TIME: i64 = 253_402_300_799;

#[derive(Default, Clone, Debug, PartialEq)]
pub struct NvrState {
    /// Device time up to which the log has been read.
    pub since: i64,
    /// Device clock minus host clock at the last successful read, used to
    /// notice the device clock jumping. `None` (`-` in the file): not known,
    /// because a log window was skipped while a resync was due; the next read
    /// resyncs.
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

/// Feeds what is written to a hash, so that the state can be compared with
/// what was saved without a copy of it.
struct HashWriter(std::collections::hash_map::DefaultHasher);

impl Write for HashWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Why a state file was not used.
fn unusable(path: &Path, why: &str, now: u64) -> Result<State, String> {
    let mut aside = path.as_os_str().to_owned();
    aside.push(format!(".unusable-{}", now));
    let aside = PathBuf::from(aside);
    match std::fs::rename(path, &aside) {
        Ok(()) => {
            crate::warn!(
                "state file {} {}; it is not used and was moved to {} (it may hold the only \
                 record of what is banned); starting with an empty state",
                path.display(),
                why,
                aside.display()
            );
            Ok(State::default())
        }
        Err(e) => Err(format!(
            "state file {} {}, and it cannot be moved aside ({}); not starting, so that the \
             next save does not overwrite it",
            path.display(),
            why,
            e.kind()
        )),
    }
}

impl State {
    /// Writes the state in its file format.
    pub fn write_to(&self, out: &mut impl Write) -> std::io::Result<()> {
        writeln!(out, "{}", HEADER)?;
        for (name, st) in &self.nvr {
            match st.offset {
                Some(o) => writeln!(out, "nvr {} {} {}", name, st.since, o)?,
                None => writeln!(out, "nvr {} {} -", name, st.since)?,
            }
            let mut seen: Vec<_> = st.seen.iter().collect();
            seen.sort();
            for (key, count) in seen {
                writeln!(out, "seen {} {} {}", name, key, count)?;
            }
        }
        for (ip, times) in &self.fails {
            for t in times {
                writeln!(out, "fail {} {}", ip, t)?;
            }
        }
        for (ip, until) in &self.banned {
            writeln!(out, "ban {} {}", ip, until)?;
        }
        for (ip, p) in &self.pending {
            writeln!(
                out,
                "pending {} {} {} {} {}",
                ip, p.ts, p.count, p.nvr, p.user
            )?;
        }
        for t in &self.recent_bans {
            writeln!(out, "rate {}", t)?;
        }
        Ok(())
    }

    pub fn serialize(&self) -> String {
        let mut out = Vec::new();
        self.write_to(&mut out).expect("writing to memory");
        String::from_utf8(out).expect("the state is ASCII")
    }

    /// A hash of the serialized state, to tell whether it changed since it
    /// was saved without keeping a copy (equal states give equal hashes
    /// within one run).
    pub fn digest(&self) -> u64 {
        let mut hasher = HashWriter(Default::default());
        self.write_to(&mut hasher).expect("writing to a hash");
        hasher.0.finish()
    }

    pub fn parse(text: &str) -> State {
        let mut lines = text.lines();
        if lines.next().map(str::trim) != Some(HEADER) {
            return State::default();
        }
        State::parse_lines(lines).0
    }

    /// The state from the lines after the header, and how many lines were
    /// ignored (not understood, out of range or beyond a bound).
    fn parse_lines<'a>(lines: impl Iterator<Item = &'a str>) -> (State, usize) {
        let mut st = State::default();
        let mut ignored = 0;
        let mut reader = Reader::default();
        for line in lines {
            if !reader.line(&mut st, line) {
                ignored += 1;
            }
        }
        ignored += reader.finish(&mut st);
        (st, ignored)
    }
}

/// Reads a state file line by line.
#[derive(Default)]
struct Reader {
    /// An NVR is known only through a valid `nvr` line: `seen` lines alone
    /// must not fake a read position of 0.
    positioned: std::collections::HashSet<String>,
}

impl Reader {
    /// Takes one line into `st`; false when the line is not used.
    fn line(&mut self, st: &mut State, line: &str) -> bool {
        let positioned = &mut self.positioned;
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
                let (Some(since), Some(offset)) = (time(since), offset) else {
                    return false;
                };
                let nvr = st.nvr.entry(name.to_string()).or_default();
                nvr.since = since;
                nvr.offset = offset;
                positioned.insert(name.to_string());
                true
            }
            ["seen", name, key, count] if name_ok(name) && key_ok(key) => {
                let Some(count) = count.parse::<u32>().ok().filter(|c| *c <= 1_000_000) else {
                    return false;
                };
                let nvr = st.nvr.entry(name.to_string()).or_default();
                if nvr.seen.len() >= MAX_SEEN {
                    return false;
                }
                nvr.seen.insert(key.to_string(), count);
                true
            }
            ["fail", ip, t] => {
                let (Ok(ip), Some(t)) = (ip.parse::<Ipv4Addr>(), time(t)) else {
                    return false;
                };
                if st.fails.len() >= MAX_TRACKED && !st.fails.contains_key(&ip) {
                    return false;
                }
                let times = st.fails.entry(ip).or_default();
                if times.len() >= MAX_TIMES {
                    return false;
                }
                times.push(t);
                true
            }
            ["ban", ip, until] => {
                let (Ok(ip), Some(until)) = (ip.parse::<Ipv4Addr>(), utime(until)) else {
                    return false;
                };
                if st.banned.len() >= MAX_BANNED {
                    return false;
                }
                st.banned.insert(ip, until);
                true
            }
            ["pending", ip, ts, count, nvr, user @ ..] if name_ok(nvr) => {
                let count = count
                    .parse::<usize>()
                    .ok()
                    .filter(|c| (1..=1_000_000).contains(c));
                let (Ok(ip), Some(ts), Some(count)) = (ip.parse::<Ipv4Addr>(), time(ts), count)
                else {
                    return false;
                };
                if st.pending.len() >= MAX_PENDING {
                    return false;
                }
                st.pending.insert(
                    ip,
                    Pending {
                        ts,
                        count,
                        nvr: nvr.to_string(),
                        user: crate::util::sanitize(&user.join(" "), 64),
                    },
                );
                true
            }
            ["rate", t] => {
                let Some(t) = utime(t) else {
                    return false;
                };
                if st.recent_bans.len() >= MAX_RATE {
                    return false;
                }
                st.recent_bans.push(t);
                true
            }
            _ => false,
        }
    }

    /// Ends the reading: drops `seen` lines of NVRs without a position and
    /// sorts what needs order. Returns the number of lines dropped.
    fn finish(self, st: &mut State) -> usize {
        let mut dropped = 0;
        st.nvr.retain(|name, nvr| {
            let keep = self.positioned.contains(name);
            if !keep {
                dropped += nvr.seen.len();
            }
            keep
        });
        for times in st.fails.values_mut() {
            times.sort_unstable();
        }
        dropped
    }
}

impl State {
    /// Reads the state file. A missing file is a first start. A file that
    /// cannot be used is reported at WARNING level and moved aside (see the
    /// module comment); an error only when that fails. Lines that cannot be
    /// used are ignored, with one WARNING that counts them.
    pub fn load(path: &Path) -> Result<State, String> {
        State::load_at(path, crate::util::unix_now())
    }

    /// `load`, with the host time that names a file moved aside.
    pub fn load_at(path: &Path, now: u64) -> Result<State, String> {
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                crate::info!(
                    "no state file at {} yet: starting with an empty state",
                    path.display()
                );
                return Ok(State::default());
            }
            Err(e) => return unusable(path, &format!("cannot be opened ({})", e.kind()), now),
        };
        match file.metadata() {
            Ok(m) if m.is_dir() => return unusable(path, "is a directory", now),
            Ok(m) if m.len() > MAX_FILE => {
                let why = format!("is larger than {} MiB ({} bytes)", MAX_FILE >> 20, m.len());
                return unusable(path, &why, now);
            }
            Ok(_) => {}
            Err(e) => return unusable(path, &format!("cannot be read ({})", e.kind()), now),
        }
        let mut reader = std::io::BufReader::new(std::io::Read::take(file, MAX_FILE + 1));
        let mut line = String::new();
        let mut header = true;
        let mut state = State::default();
        let mut ignored = 0;
        let mut lines = Reader::default();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                    return unusable(path, "is not text", now)
                }
                Err(e) => return unusable(path, &format!("cannot be read ({})", e.kind()), now),
            }
            let text = line.trim_end_matches(['\n', '\r']);
            if header {
                header = false;
                if text.trim() == HEADER {
                    continue;
                }
                let why = if text.starts_with("hik-f2b-state ") {
                    format!(
                        "was written by another version of hik-f2b ({:?}, this one reads {:?})",
                        crate::util::sanitize(text, 40),
                        HEADER
                    )
                } else {
                    format!(
                        "is not a hik-f2b state file (its first line is {:?})",
                        crate::util::sanitize(text, 40)
                    )
                };
                return unusable(path, &why, now);
            }
            if !lines.line(&mut state, text) {
                ignored += 1;
            }
        }
        if header {
            return unusable(path, "is empty", now);
        }
        ignored += lines.finish(&mut state);
        if ignored > 0 {
            crate::warn!(
                "state file {}: {} line(s) could not be used and were ignored (damaged, out of \
                 range or beyond a limit); the rest is used",
                path.display(),
                ignored
            );
        }
        Ok(state)
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
        let file = options.open(&tmp)?;
        let mut out = std::io::BufWriter::new(file);
        self.write_to(&mut out)?;
        let file = out.into_inner().map_err(|e| e.into_error())?;
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

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("hik-f2b-state-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn unusable_files_are_kept_aside() {
        const NOW: u64 = 1_700_000_000;
        let dir = temp_dir("unusable");
        let path = dir.join("state");
        let aside = dir.join(format!("state.unusable-{}", NOW));
        crate::util::capture_log();

        // a first start: nothing to say beyond that, nothing created
        assert_eq!(State::load_at(&path, NOW), Ok(State::default()));
        assert!(!path.exists());
        let log = crate::util::captured_log();
        assert!(log[0].contains("no state file at"), "{:?}", log);

        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "written by another version",
                b"hik-f2b-state 1\nfail 198.51.100.7 5\n".to_vec(),
            ),
            (
                "is not a hik-f2b state file",
                b"something else\nban 198.51.100.7 5\n".to_vec(),
            ),
            (
                "is not text",
                b"hik-f2b-state 2\nban 198.51.100.7 \xff\xfe\n".to_vec(),
            ),
            ("is empty", Vec::new()),
        ];
        for (why, content) in cases {
            std::fs::write(&path, &content).unwrap();
            assert_eq!(State::load_at(&path, NOW), Ok(State::default()), "{}", why);
            assert!(!path.exists(), "{}", why);
            assert_eq!(std::fs::read(&aside).unwrap(), content, "{}", why);
            std::fs::remove_file(&aside).unwrap();
            let log = crate::util::captured_log();
            assert_eq!(log.len(), 1, "{:?}", log);
            assert!(log[0].starts_with("WARNING state file "), "{}", log[0]);
            assert!(log[0].contains(why), "{}: {}", why, log[0]);
            assert!(log[0].contains("was moved to"), "{}", log[0]);
        }
        // too large: not even read
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_FILE + 1).unwrap();
        drop(file);
        assert_eq!(State::load_at(&path, NOW), Ok(State::default()));
        assert_eq!(std::fs::metadata(&aside).unwrap().len(), MAX_FILE + 1);
        assert!(crate::util::captured_log()[0].contains("is larger than 16 MiB"));
        std::fs::remove_file(&aside).unwrap();

        // when it cannot be moved aside, hik-f2b does not start
        std::fs::write(&path, b"hik-f2b-state 1\n").unwrap();
        std::fs::create_dir_all(aside.join("in-the-way")).unwrap();
        let err = State::load_at(&path, NOW).err().unwrap();
        assert!(err.contains("cannot be moved aside"), "{}", err);
        assert!(err.contains("not starting"), "{}", err);
        assert_eq!(std::fs::read(&path).unwrap(), b"hik-f2b-state 1\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn damaged_lines_are_counted() {
        let dir = temp_dir("damaged");
        let path = dir.join("state");
        std::fs::write(
            &path,
            "hik-f2b-state 2\r\nban 198.51.100.7 99\r\nban 198.51.100.8 x\r\nwhatever\r\n\
             seen ghost 0123456789abcdef0123456789abcdef 1\r\n",
        )
        .unwrap();
        crate::util::capture_log();
        let st = State::load_at(&path, 5).unwrap();
        assert_eq!(st.banned.len(), 1);
        assert!(st.nvr.is_empty());
        let log = crate::util::captured_log();
        assert_eq!(log.len(), 1, "{:?}", log);
        assert!(log[0].contains("3 line(s) could not be used"), "{}", log[0]);
        // the file is used, so it stays where it is
        assert!(path.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Every collection at its bound, as two busy NVRs and a long attack can
    /// leave it: the file stays below `MAX_FILE`, so it is read back.
    #[test]
    fn a_full_state_fits_the_file_limit() {
        let mut st = State::default();
        for name in ["nvr1", "nvr2"] {
            let nvr = st.nvr.entry(name.to_string()).or_default();
            nvr.since = MAX_TIME;
            nvr.offset = Some(-MAX_TIME);
            for i in 0..MAX_SEEN {
                nvr.seen
                    .insert(format!("{:032x}", u128::MAX - i as u128), 1_000_000);
            }
        }
        let address = |i: usize| Ipv4Addr::from(0xC000_0000u32 + i as u32);
        let per_address = MAX_FAIL_TIMES / MAX_TRACKED;
        for i in 0..MAX_TRACKED {
            st.fails.insert(address(i), vec![MAX_TIME; per_address]);
        }
        for i in 0..MAX_BANNED {
            st.banned.insert(address(i), MAX_TIME as u64);
        }
        for i in 0..MAX_PENDING {
            st.pending.insert(
                address(i),
                Pending {
                    ts: MAX_TIME,
                    count: 1_000_000,
                    nvr: "x".repeat(32),
                    user: "u".repeat(32),
                },
            );
        }
        st.recent_bans = vec![MAX_TIME as u64; MAX_RATE];
        let size = st.serialize().len() as u64;
        println!("a full state with two NVRs: {} bytes", size);
        assert!(size <= MAX_FILE, "{} bytes", size);
        let dir = temp_dir("full");
        let path = dir.join("state");
        st.save(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), size);
        assert_eq!(State::load_at(&path, 5).unwrap(), st);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn digest_follows_the_content() {
        let mut st = State::default();
        let empty = st.digest();
        assert_eq!(State::default().digest(), empty);
        st.recent_bans.push(5);
        assert_ne!(st.digest(), empty);
        st.recent_bans.clear();
        assert_eq!(st.digest(), empty);
    }
}
