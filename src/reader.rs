//! One NVR log reader per NVR: the rules of reading one NVR's log.
//!
//! The reader owns what reading needs: the client, the read cursor that the
//! state file keeps (`since`, `offset`, `seen`), the counters kept in memory
//! (failed polls, the login backoff), the rules for a device clock that
//! jumped and for a resync, the search window (order, paging, the caps) and
//! the conversion of device time to host time. It is asked once per poll,
//! at a host time (`LogReader::poll`), and answers with the new failed
//! logins in host time inside the counting window, or that it was not
//! tried, or why the read failed. The rest of the engine never sees device
//! time.
//!
//! The cursors of all NVRs (`Cursors`) are part of the state, which is
//! saved, loaded and replaced as a whole; this module writes and reads
//! their lines of the state file. The reader gets its log through
//! `LogSource`: the NVR client (`Nvr`), or an in-memory log in the unit
//! tests.

use crate::config::Config;
use crate::ledger::MAX_FUTURE;
use crate::nvr::{Event, Nvr, NvrError, Search};
use crate::state::{time, MAX_TIME};
use crate::util::{self, host_i64};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::net::IpAddr;

/// Polls in a row that may fail for a reason other than authentication
/// before the read cursor is moved past whatever blocks it.
const MAX_FAILED_POLLS: u32 = 10;
/// A change of the device-minus-host offset larger than this between two
/// reads, in either direction, is a clock jump, not drift or a slow
/// request. Well below a DST change, well above what slow polls of several
/// NVRs add up to. A smaller change is taken as it is: entries logged before
/// it and read after it are converted with the new offset, so their host
/// times can be off by up to this much.
pub const CLOCK_JUMP: i64 = 900;
/// Searches of one NVR's log per poll, when the NVR lists newest first and
/// the window holds more than one search returns (see `read_window`). With
/// the caps in `nvr.rs` one poll reads at most this many times 50 pages or
/// 5000 entries.
const MAX_SEARCHES: usize = 4;
/// Upper bound on remembered log entries per NVR.
pub const MAX_SEEN: usize = 50_000;

/// What the reader needs from an NVR: its clock and a search of its log.
pub trait LogSource {
    /// The device's own wall-clock time.
    fn now(&mut self) -> Result<i64, NvrError>;
    /// The log entries of type `meta_id` between `start` and `end` (device
    /// time), in the order the NVR lists them, up to a cap (`truncated`
    /// says whether it was hit).
    fn search(&mut self, start: i64, end: i64, meta_id: &str) -> Result<Search, NvrError>;
}

impl LogSource for Nvr {
    fn now(&mut self) -> Result<i64, NvrError> {
        Nvr::now(self)
    }

    fn search(&mut self, start: i64, end: i64, meta_id: &str) -> Result<Search, NvrError> {
        Nvr::search(self, start, end, meta_id, None)
    }
}

/// Where one NVR's log was read up to; the state file keeps it.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct Cursor {
    /// Device time up to which the log has been read.
    since: i64,
    /// Device clock minus host clock at the last successful read, used to
    /// notice the device clock jumping. `None` (`-` in the file): not known,
    /// because a log window was skipped while a resync was due, or a resync
    /// could not read its whole window; the next read resyncs.
    offset: Option<i64>,
    /// Entries seen in the last (overlapping) query window, by key hash.
    seen: HashMap<String, u32>,
}

impl Cursor {
    /// Device time up to which the log has been read.
    pub fn since(&self) -> i64 {
        self.since
    }

    /// Device clock minus host clock at the last read; `None` when it is
    /// not known and the next read resyncs.
    pub fn offset(&self) -> Option<i64> {
        self.offset
    }

    /// How many log entries are remembered as seen.
    pub fn seen(&self) -> usize {
        self.seen.len()
    }
}

/// The read cursor of every NVR, by name: the `nvr` and `seen` lines of the
/// state file. An NVR has one once its first read succeeded.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct Cursors {
    by_name: BTreeMap<String, Cursor>,
}

impl Cursors {
    pub fn get(&self, nvr: &str) -> Option<&Cursor> {
        self.by_name.get(nvr)
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// The cursors, by NVR name in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Cursor)> {
        self.by_name
            .iter()
            .map(|(name, cursor)| (name.as_str(), cursor))
    }

    /// Writes the `nvr` and `seen` lines of the state file.
    pub(crate) fn write_to(&self, out: &mut impl Write) -> std::io::Result<()> {
        for (name, st) in &self.by_name {
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
        Ok(())
    }
}

impl std::ops::Index<&str> for Cursors {
    type Output = Cursor;

    /// The cursor of an NVR that has one.
    fn index(&self, nvr: &str) -> &Cursor {
        &self.by_name[nvr]
    }
}

/// An NVR name as the configuration allows it.
fn name_ok(text: &str) -> bool {
    util::is_name(text, 32)
}

fn key_ok(text: &str) -> bool {
    text.len() == 32 && text.chars().all(|c| c.is_ascii_hexdigit())
}

/// Reads the `nvr` and `seen` lines of a state file into `Cursors`.
#[derive(Default)]
pub(crate) struct CursorLines {
    /// An NVR is known only through a valid `nvr` line: `seen` lines alone
    /// must not fake a read position of 0.
    positioned: HashSet<String>,
}

impl CursorLines {
    /// Takes one line, split at spaces: `None` when it is not a cursor line,
    /// else whether it was used.
    pub(crate) fn line(&mut self, cursors: &mut Cursors, f: &[&str]) -> Option<bool> {
        let positioned = &mut self.positioned;
        match f {
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
                    return Some(false);
                };
                let nvr = cursors.by_name.entry(name.to_string()).or_default();
                nvr.since = since;
                nvr.offset = offset;
                positioned.insert(name.to_string());
                Some(true)
            }
            ["seen", name, key, count] if name_ok(name) && key_ok(key) => {
                let Some(count) = count.parse::<u32>().ok().filter(|c| *c <= 1_000_000) else {
                    return Some(false);
                };
                let nvr = cursors.by_name.entry(name.to_string()).or_default();
                if nvr.seen.len() >= MAX_SEEN {
                    return Some(false);
                }
                nvr.seen.insert(key.to_string(), count);
                Some(true)
            }
            _ => None,
        }
    }

    /// Ends the reading: drops `seen` lines of NVRs without a position.
    /// Returns the number of lines dropped.
    pub(crate) fn finish(self, cursors: &mut Cursors) -> usize {
        let mut dropped = 0;
        cursors.by_name.retain(|name, nvr| {
            let keep = self.positioned.contains(name);
            if !keep {
                dropped += nvr.seen.len();
            }
            keep
        });
        dropped
    }
}

/// The log reader of one NVR.
pub struct LogReader<L: LogSource = Nvr> {
    name: String,
    log: L,
    /// Polls in a row that failed for a reason other than our login being
    /// rejected (kept in memory only).
    failed_polls: u32,
    /// Host time before which this NVR is not contacted (after a rejected
    /// login).
    retry_after: u64,
    /// A resync whose read was cut is due, and that was said (kept in memory
    /// only: after a restart it is said once more).
    cut_said: bool,
}

/// What one poll of an NVR gave.
pub enum Poll {
    /// Not tried: the reader backs off after a rejected login.
    BackingOff,
    /// The NVR could not be read: its login was rejected (`NvrError::Auth`,
    /// the reader now backs off for `auth_backoff`) or something else
    /// failed.
    Failed(NvrError),
    /// The log was read; these are the new failed logins.
    Read(Logins),
}

/// One new failed login, in host time.
#[derive(Debug, PartialEq)]
pub struct Login {
    pub nvr: String,
    pub ip: IpAddr,
    /// Whatever the remote party typed: hostile text.
    pub user: String,
    /// Host time.
    pub at: i64,
}

/// The new failed logins of one poll, oldest first, in host time and inside
/// the counting window (`findtime` back from the host time of the poll, up
/// to `MAX_FUTURE` ahead). An entry outside it is passed over with a DEBUG
/// line when the iteration reaches it, so that the log keeps its order.
pub struct Logins {
    fresh: std::vec::IntoIter<Event>,
    offset: i64,
    now: i64,
    findtime: i64,
}

impl Iterator for Logins {
    type Item = Login;

    fn next(&mut self) -> Option<Login> {
        for ev in self.fresh.by_ref() {
            let Some(ts) = ev.ts else { continue };
            let host_ts = ts.saturating_sub(self.offset);
            if host_ts < self.now.saturating_sub(self.findtime)
                || host_ts > self.now.saturating_add(MAX_FUTURE)
            {
                crate::debug!(
                    "{}: entry at {} (device time) is outside the counting window, not counted",
                    ev.nvr,
                    util::fmt_ts(ts)
                );
                continue;
            }
            // `read_log` passes on no entry without an address
            let Some(ip) = ev.ip else { continue };
            return Some(Login {
                nvr: ev.nvr,
                ip,
                user: ev.user,
                at: host_ts,
            });
        }
        None
    }
}

impl<L: LogSource> LogReader<L> {
    /// The reader of the NVR `name`, whose log `log` gives.
    pub fn new(name: &str, log: L) -> LogReader<L> {
        LogReader {
            name: name.to_string(),
            log,
            failed_polls: 0,
            retry_after: 0,
            cut_said: false,
        }
    }

    /// The NVR's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The log source, for what is not a poll (the unit tests set up their
    /// log in memory through it).
    pub fn client(&mut self) -> &mut L {
        &mut self.log
    }

    /// Polls in a row whose log could not be read (0 after a read).
    pub fn failed_polls(&self) -> u32 {
        self.failed_polls
    }

    /// Host time before which the NVR is not contacted after a rejected
    /// login; 0 when there is none.
    pub fn retry_after(&self) -> u64 {
        self.retry_after
    }

    /// One poll at host time `host_now`, with the cursors of the state.
    pub fn poll(&mut self, cursors: &mut Cursors, cfg: &Config, host_now: u64) -> Poll {
        let retry_after = self.retry_after;
        if retry_after > host_now {
            // A wait longer than auth_backoff can only come from the
            // host clock jumping back; do not wait for years.
            if retry_after - host_now <= cfg.auth_backoff {
                return Poll::BackingOff;
            }
            self.retry_after = 0;
        }
        let now = host_i64(host_now);
        match self.poll_nvr(cfg, &mut cursors.by_name, now) {
            Err(NvrError::Auth(e)) => {
                self.retry_after = host_now.saturating_add(cfg.auth_backoff);
                Poll::Failed(NvrError::Auth(e))
            }
            Err(e) => Poll::Failed(e),
            Ok(polled) => Poll::Read(Logins {
                fresh: polled.fresh.into_iter(),
                offset: polled.offset,
                now,
                findtime: cfg.findtime,
            }),
        }
    }

    /// Reads the NVR's log. Owns the read cursor (`since`, device time) and
    /// the `seen` set.
    ///
    /// The first poll of an NVR reads from its current time. It records what
    /// the `lookback` overlap before that holds as already seen, without
    /// counting it, so failed logins from before the start are never counted.
    /// Until that read succeeds, and reads its whole window, the NVR stays
    /// unknown, and the next poll tries again.
    fn poll_nvr(
        &mut self,
        cfg: &Config,
        cursors: &mut BTreeMap<String, Cursor>,
        host_now: i64,
    ) -> Result<Polled, NvrError> {
        // An NVR that cannot be reached at all does not count towards skipping
        // a log window (`failed_polls`): only a log that cannot be read does.
        let now = self.log.now()?;
        let offset = now.saturating_sub(host_now);
        let first = !cursors.contains_key(&self.name);
        let st = cursors.entry(self.name.clone()).or_insert_with(|| Cursor {
            since: now,
            offset: Some(offset),
            ..Default::default()
        });
        let result = self.read_log(cfg, st, now, offset, first);
        // a first read that was cut left the resync due (`offset` unknown)
        if first && (result.is_err() || st.offset.is_none()) {
            cursors.remove(&self.name);
        }
        result
    }

    /// `poll_nvr` once the NVR's cursor exists (`first`: it was just made).
    ///
    /// What keeps an entry from being counted twice: `seen` holds every entry
    /// of the last window read, which started at `since - lookback`. So a
    /// window may start there or later, but never earlier: what lies before
    /// that start is not in `seen`. Every write of `since` keeps to this:
    ///
    /// - A read without a baseline moves `since` to the newest entry read, or
    ///   on, but never back: the device clock is at or after `since`.
    /// - When the device clock is behind `since` (it went back, by any amount),
    ///   or the offset changed by more than `CLOCK_JUMP` in either direction, a
    ///   baseline resyncs: the window starts at the new time, and what it holds
    ///   is recorded as seen, not counted. A step back on a quiet NVR leaves the
    ///   clock ahead of `since` (which trails it by `findtime + lookback`), so
    ///   only the offset shows it; entries logged before it and read after it
    ///   (after an outage, say) would otherwise be converted with the wrong
    ///   offset.
    /// - A skipped window (`MAX_FAILED_POLLS`) moves `since` without a read.
    ///   If a baseline was due, the offset is cleared (`None`), so the next read
    ///   that works is a baseline.
    /// - A baseline is complete only if it read its whole window. One that was
    ///   cut (the window holds more than the searches of one poll return)
    ///   records what it read as seen, moves `since` to the device time and
    ///   clears the offset too: the next poll resyncs again from its own time,
    ///   and nothing of the NVR is counted until a baseline reads its whole
    ///   window. Otherwise the part it did not read, which can hold entries
    ///   from before the change, would be counted later.
    ///
    /// `since` is never ahead of the device clock, so that the clock going back
    /// is noticed at the next poll.
    fn read_log(
        &mut self,
        cfg: &Config,
        st: &mut Cursor,
        now: i64,
        offset: i64,
        first: bool,
    ) -> Result<Polled, NvrError> {
        let lookback = cfg.lookback;
        // After a clock jump the device log holds entries whose times say
        // nothing about when they happened relative to new ones. Resync: read
        // from the new time, and record what the first window holds without
        // counting it, so old entries are never counted (again).
        let jump = if first {
            None
        } else if st.offset.is_none() {
            Some(format!(
                "no device clock offset is known (the read position was moved to {} without a read)",
                util::fmt_ts(st.since)
            ))
        } else if now < st.since {
            Some(format!(
                "device clock went back from {} to {}",
                util::fmt_ts(st.since),
                util::fmt_ts(now)
            ))
        } else {
            st.offset
                .map(|previous| offset.saturating_sub(previous))
                .filter(|jump| jump.unsigned_abs() > CLOCK_JUMP.unsigned_abs())
                .map(|jump| {
                    format!(
                        "device clock jumped {} by {} s (to {})",
                        if jump > 0 { "forward" } else { "back" },
                        jump.unsigned_abs(),
                        util::fmt_ts(now)
                    )
                })
        };
        let baseline = first || jump.is_some();
        // A resync that goes on from a cut one of this run: the cut was said.
        let continued = self.cut_said && st.offset.is_none();
        let previous = st.since;
        let mut since = st.since;
        if let Some(jump) = &jump {
            if !continued {
                crate::warn!(
                    "{}: {}; reading on from the new time, entries already in the log are not \
                     counted",
                    self.name,
                    jump
                );
            }
            since = now;
        }
        // Entries older than findtime cannot contribute to a ban; skipping them
        // also avoids reading the whole log history after a long outage.
        let horizon = now.saturating_sub(cfg.findtime.saturating_add(lookback));
        if since < horizon {
            crate::debug!(
                "{}: skipping log entries before {} (older than findtime)",
                self.name,
                util::fmt_ts(horizon)
            );
            since = horizon;
        }

        let result = read_window(
            &mut self.log,
            &self.name,
            since.saturating_sub(lookback),
            now.saturating_add(86400),
            &cfg.meta_id,
        );
        let window = match result {
            Ok(window) => window,
            // On the first run there is no cursor to move on: the next poll
            // starts from its own time anyway.
            Err(NvrError::Other(e)) if first => return Err(NvrError::Other(e)),
            Err(NvrError::Other(e)) => {
                self.failed_polls = self.failed_polls.saturating_add(1);
                if self.failed_polls >= MAX_FAILED_POLLS {
                    // Without this a single entry the NVR cannot deliver would
                    // stop the daemon from ever reading on.
                    crate::error!(
                        "{}: the log could not be read {} times in a row; SKIPPING the log window \
                         {} .. {} (device time), failed logins in it are not counted{}",
                        self.name,
                        self.failed_polls,
                        util::fmt_ts(since.saturating_sub(lookback)),
                        util::fmt_ts(now),
                        if baseline {
                            "; the device clock changed, so the next read records the log as \
                             already seen"
                        } else {
                            ""
                        }
                    );
                    st.since = now;
                    // The cursor moved without a read: if a resync was due, it
                    // stays due (see above), now for this reason.
                    st.offset = if baseline { None } else { Some(offset) };
                    self.cut_said = false;
                    self.failed_polls = 0;
                }
                return Err(NvrError::Other(e));
            }
            Err(e) => return Err(e),
        };
        self.failed_polls = 0;

        // The search window overlaps the previous one, so an entry is new only
        // if it occurs more often than it did in the previous poll.
        let mut counter: HashMap<String, u32> = HashMap::new();
        let mut fresh = Vec::new();
        let newest = window.newest.map_or(since, |ts| ts.max(since));
        for ev in window.events {
            if !cfg.log_filter.is_match(&ev.meta) {
                continue;
            }
            if ev.ts.is_none() || ev.ip.is_none() {
                crate::debug!("{}: entry without time or address skipped", self.name);
                continue;
            }
            let n = counter.entry(ev.key.clone()).or_insert(0);
            *n = n.saturating_add(1);
            if !baseline && *n > st.seen.get(&ev.key).copied().unwrap_or(0) {
                fresh.push(ev);
            }
        }
        let entries = if counter.len() == 1 { "y" } else { "ies" };
        if baseline && !window.whole {
            if !self.cut_said {
                crate::warn!(
                    "{}: {}the log holds more entries from {} (device time) on than one read \
                     returns, so not all of them can be recorded as already seen; failed logins \
                     of this NVR are not counted until the log can be read whole",
                    self.name,
                    if first { "first run: " } else { "" },
                    util::fmt_ts(since.saturating_sub(lookback))
                );
                self.cut_said = true;
            }
            // The resync stays due (see above); `fresh` is empty.
            st.seen = counter;
            st.since = now;
            st.offset = None;
            return Ok(Polled { fresh, offset });
        }
        self.cut_said = false;
        if first {
            crate::info!(
                "{}: first run, watching log entries from {} (device time); {} log entr{} from \
                 before the start recorded as already seen, not counted",
                self.name,
                util::fmt_ts(now),
                counter.len(),
                entries
            );
        } else if baseline {
            crate::info!(
                "{}: {} existing log entr{} recorded as already seen",
                self.name,
                counter.len(),
                entries
            );
        }
        fresh.sort_by_key(|ev| ev.ts);

        let mut next = newest.min(now);
        if window.cut_after && !baseline {
            // Only the start of the window was read: entries seen before that
            // were not re-read this time must stay known, or the next poll would
            // count them again.
            if st.seen.len() + counter.len() <= MAX_SEEN {
                for (key, count) in counter {
                    let n = st.seen.entry(key).or_insert(0);
                    *n = (*n).max(count);
                }
            } else {
                st.seen = counter;
            }
            if next <= since {
                next = since.saturating_add(1).min(now);
                crate::warn!(
                    "{}: more log entries within one second than can be read in one poll; \
                     moving on by one second, some entries may have been skipped",
                    self.name
                );
            }
        } else {
            st.seen = counter;
        }
        // Never ahead of the device clock, or a step back to before the newest
        // entry read, however small, would go unseen.
        st.since = next.min(now);
        // Without a baseline the device clock is at or after `previous`, so the
        // next window never starts before this one (see above).
        debug_assert!(baseline || st.since >= previous);
        st.offset = Some(offset);
        Ok(Polled { fresh, offset })
    }
}

/// New failed logins of one NVR and the offset (device minus host time)
/// that converts their times to host time.
struct Polled {
    fresh: Vec<Event>,
    offset: i64,
}

/// What one poll read from an NVR's log window.
struct Window {
    /// Each entry read, once, however many searches it took.
    events: Vec<Event>,
    /// The newest entry time read (device time).
    newest: Option<i64>,
    /// Entries newer than `newest` may not have been read (the NVR lists
    /// oldest first, or the order could not be told): the cursor must not
    /// move past `newest`.
    cut_after: bool,
    /// Every entry of the window was read.
    whole: bool,
}

/// Reads the log window `start ..= end` (device time) of one NVR.
///
/// A search stops at the cap in `nvr.rs`. The times of the entries a capped
/// search returned tell which end of the window it read:
///
/// - Oldest first (both tested NVRs): the rest is newer. `cut_after` is
///   set, and the caller keeps its cursor at the newest entry read, so the
///   next poll reads on from there.
/// - Newest first: the rest is older, and a cursor can never reach it.
///   Further searches read it now, each ending just after the oldest
///   second read so far, up to `MAX_SEARCHES` in all. A search may stop in
///   the middle of a second; that second is read again by the next search
///   and taken from that search only, so no entry is counted twice. What
///   cannot be read within the bound is reported as an ERROR.
/// - All entries in one second: the order cannot be told. What was read is
///   kept, the older part is read as for newest first, and `cut_after` is
///   set as for oldest first.
///
/// `whole` is set only if none of this left an entry of the window unread.
fn read_window<L: LogSource>(
    log: &mut L,
    name: &str,
    start: i64,
    end: i64,
    meta_id: &str,
) -> Result<Window, NvrError> {
    let mut window = Window {
        events: Vec::new(),
        newest: None,
        cut_after: false,
        whole: false,
    };
    let mut end = end;
    // Entries of one second were left out (the WARNING below).
    let mut skipped = false;
    // Entries after this came from an earlier search of this poll.
    let mut keep_to: Option<i64> = None;
    for n in 0..MAX_SEARCHES {
        let search = log.search(start, end, meta_id)?;
        let first = search.events.iter().find_map(|ev| ev.ts);
        let last = search.events.iter().rev().find_map(|ev| ev.ts);
        let newest_first = matches!((first, last), (Some(f), Some(l)) if f > l);
        let kept: Vec<Event> = search
            .events
            .into_iter()
            .filter(|ev| keep_to.is_none_or(|to| ev.ts.is_some_and(|ts| ts <= to)))
            .collect();
        let oldest = kept.iter().filter_map(|ev| ev.ts).min();
        let newest = kept.iter().filter_map(|ev| ev.ts).max();
        window.newest = window.newest.max(newest);
        if !search.truncated {
            window.events.extend(kept);
            window.whole = !window.cut_after && !skipped;
            return Ok(window);
        }
        let Some(oldest) = oldest else {
            if n == 0 {
                // nothing with a time to go by: keep the cursor where it is
                window.events.extend(kept);
                window.cut_after = true;
                return Ok(window);
            }
            break;
        };
        let unread_to = if oldest == newest.unwrap_or(oldest) {
            if n > 0 {
                crate::warn!(
                    "{}: more log entries within one second ({}, device time) than one search \
                     can read; some entries of that second may have been skipped",
                    name,
                    util::fmt_ts(oldest)
                );
                skipped = true;
            }
            window.cut_after |= n == 0;
            window.events.extend(kept);
            end = oldest.saturating_sub(1);
            oldest.saturating_sub(1)
        } else if newest_first {
            // the second the search stopped in is left to the next search
            window.events.extend(
                kept.into_iter()
                    .filter(|ev| ev.ts.is_some_and(|ts| ts > oldest)),
            );
            end = oldest.saturating_add(1);
            oldest
        } else if n == 0 {
            window.events.extend(kept);
            window.cut_after = true;
            return Ok(window);
        } else {
            // oldest first after a search that was newest first: the order
            // cannot be relied on, stop here
            window.events.extend(kept);
            break;
        };
        keep_to = Some(unread_to);
        if unread_to < start {
            window.whole = !window.cut_after && !skipped;
            return Ok(window);
        }
    }
    if let Some(to) = keep_to {
        crate::error!(
            "{}: not every log entry in {} .. {} (device time) could be read with {} searches \
             in one poll; SKIPPING the rest of it, failed logins in it are not counted",
            name,
            util::fmt_ts(start),
            util::fmt_ts(to),
            MAX_SEARCHES
        );
    }
    Ok(window)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::State;
    use crate::util::{capture_log, captured_log, fmt_ts};

    /// Host time of the first poll.
    const H0: u64 = 1_768_000_000;
    /// Device clock minus host clock at the start.
    const SKEW: i64 = 7200;
    const FINDTIME: i64 = 600;
    const LOOKBACK: i64 = 120;
    const AUTH_BACKOFF: u64 = 900;

    /// An NVR log in memory. A search returns the entries of its window in
    /// the order the NVR lists them, at most `per_search` of them.
    struct MemoryLog {
        /// Host time of the poll, set before each one; the device clock is
        /// `skew` ahead of it.
        host: i64,
        skew: i64,
        /// Oldest first.
        entries: Vec<Event>,
        newest_first: bool,
        per_search: usize,
        /// The time cannot be asked: the NVR cannot be reached...
        down: bool,
        /// ...or refuses our login.
        refuse: bool,
        /// Every search fails.
        broken: bool,
        time_requests: usize,
        /// The window of each search, in order.
        searches: Vec<(i64, i64)>,
    }

    impl MemoryLog {
        fn new() -> MemoryLog {
            MemoryLog {
                host: 0,
                skew: SKEW,
                entries: Vec::new(),
                newest_first: false,
                per_search: 100,
                down: false,
                refuse: false,
                broken: false,
                time_requests: 0,
                searches: Vec::new(),
            }
        }
    }

    impl LogSource for MemoryLog {
        fn now(&mut self) -> Result<i64, NvrError> {
            self.time_requests += 1;
            if self.refuse {
                return Err(NvrError::Auth("HTTP 401".to_string()));
            }
            if self.down {
                return Err(NvrError::Other("connection refused".to_string()));
            }
            Ok(self.host + self.skew)
        }

        fn search(&mut self, start: i64, end: i64, _meta_id: &str) -> Result<Search, NvrError> {
            self.searches.push((start, end));
            if self.broken {
                return Err(NvrError::Other("bad XML from NVR".to_string()));
            }
            let mut events: Vec<Event> = self
                .entries
                .iter()
                .filter(|ev| ev.ts.is_some_and(|ts| (start..=end).contains(&ts)))
                .cloned()
                .collect();
            if self.newest_first {
                events.reverse();
            }
            let truncated = events.len() > self.per_search;
            events.truncate(self.per_search);
            Ok(Search {
                events,
                truncated,
                ..Default::default()
            })
        }
    }

    /// One NVR's reader with its cursors and a host clock.
    struct Run {
        reader: LogReader<MemoryLog>,
        cursors: Cursors,
        cfg: Config,
        host: u64,
        keys: u32,
    }

    impl Run {
        fn new() -> Run {
            Run::with_findtime(FINDTIME)
        }

        fn with_findtime(findtime: i64) -> Run {
            // the DEBUG lines are checked too; the outbox's tests turn them
            // on as well, and no test needs them off
            util::set_verbose(true);
            let cfg = Config::parse(&format!(
                "[general]\nfindtime = {}\nlookback = {}\nauth_backoff = {}\n\
                 [nvr:nvr1]\nurl = http://192.0.2.10\nuser = f2b\npassword = p\n",
                findtime, LOOKBACK, AUTH_BACKOFF
            ))
            .unwrap();
            Run {
                reader: LogReader::new("nvr1", MemoryLog::new()),
                cursors: Cursors::default(),
                cfg,
                host: H0,
                keys: 0,
            }
        }

        fn log(&mut self) -> &mut MemoryLog {
            self.reader.client()
        }

        /// The device time now.
        fn device(&mut self) -> i64 {
            self.host as i64 + self.log().skew
        }

        /// A failed login from `address` at device time `ts`.
        fn add(&mut self, ts: i64, address: &str) {
            self.keys += 1;
            let key = format!("{:032x}", self.keys);
            self.add_entry(ts, address, &key);
        }

        fn add_entry(&mut self, ts: i64, address: &str, key: &str) {
            let ev = Event {
                nvr: "nvr1".to_string(),
                ts: Some(ts),
                ip: Some(address.parse().unwrap()),
                user: "admin".to_string(),
                meta: "illegalLogin".to_string(),
                key: key.to_string(),
            };
            let entries = &mut self.log().entries;
            let at = entries.partition_point(|e| e.ts <= ev.ts);
            entries.insert(at, ev);
        }

        fn advance(&mut self, seconds: u64) {
            self.host += seconds;
        }

        fn poll(&mut self) -> Poll {
            let host = self.host as i64;
            self.reader.client().host = host;
            self.reader.poll(&mut self.cursors, &self.cfg, self.host)
        }

        /// A poll that reads: the new failed logins as (address, host time).
        fn read(&mut self) -> Vec<(String, i64)> {
            match self.poll() {
                Poll::Read(logins) => logins.map(|l| (l.ip.to_string(), l.at)).collect(),
                Poll::BackingOff => panic!("not tried"),
                Poll::Failed(e) => panic!("failed: {}", e),
            }
        }

        fn cursor(&self) -> &Cursor {
            &self.cursors["nvr1"]
        }

        /// `polls` polls 30 s apart: the failed logins they count, and the
        /// device time of the first poll after which no resync is due.
        fn read_on(&mut self, polls: usize) -> (Vec<(String, i64)>, Option<i64>) {
            let mut counted = Vec::new();
            let mut done = None;
            for _ in 0..polls {
                self.advance(30);
                counted.extend(self.read());
                let due = self
                    .cursors
                    .get("nvr1")
                    .is_none_or(|st| st.offset().is_none());
                if !due && done.is_none() {
                    done = Some(self.device());
                }
            }
            (counted, done)
        }

        /// A new reader of the same log, as after a restart of hik-f2b.
        fn restart(&mut self) {
            let old = std::mem::replace(&mut self.reader, LogReader::new("nvr1", MemoryLog::new()));
            self.reader = LogReader::new("nvr1", old.log);
        }

        /// The searches since the last call.
        fn searches(&mut self) -> Vec<(i64, i64)> {
            std::mem::take(&mut self.log().searches)
        }
    }

    fn failed_with_other(poll: Poll) -> bool {
        matches!(poll, Poll::Failed(NvrError::Other(_)))
    }

    /// How often `line` was logged.
    fn logged(log: &[String], line: &str) -> usize {
        log.iter().filter(|l| l.as_str() == line).count()
    }

    /// Lines at WARNING or ERROR level.
    fn problems(log: &[String]) -> Vec<&String> {
        log.iter()
            .filter(|l| l.starts_with("WARNING") || l.starts_with("ERROR"))
            .collect()
    }

    const A: &str = "198.51.100.7";
    const B: &str = "203.0.113.9";

    #[test]
    fn the_first_poll_records_the_overlap_as_seen_without_counting_it() {
        let mut r = Run::new();
        let d0 = r.device();
        r.add(d0 - 200, B); // before the overlap: not even read
        r.add(d0 - 60, A);
        r.add(d0 - 50, A);
        capture_log();
        assert_eq!(r.read(), vec![]);
        let log = captured_log();
        assert_eq!(
            logged(
                &log,
                &format!(
                    "INFO nvr1: first run, watching log entries from {} (device time); 2 log \
                     entries from before the start recorded as already seen, not counted",
                    fmt_ts(d0)
                )
            ),
            1,
            "{:?}",
            log
        );
        assert!(problems(&log).is_empty(), "{:?}", log);
        assert_eq!(r.searches(), vec![(d0 - LOOKBACK, d0 + 86400)]);
        assert_eq!(r.cursor().since(), d0);
        assert_eq!(r.cursor().offset(), Some(SKEW));
        assert_eq!(r.cursor().seen(), 2);

        // the overlap is read again, and still not counted
        r.advance(30);
        r.add(d0 + 10, A);
        assert_eq!(r.read(), vec![(A.to_string(), d0 + 10 - SKEW)]);
        assert_eq!(r.searches(), vec![(d0 - LOOKBACK, d0 + 30 + 86400)]);
        assert_eq!(r.cursor().since(), d0 + 10);
    }

    #[test]
    fn the_first_poll_that_fails_leaves_the_nvr_unknown() {
        let mut r = Run::new();
        r.log().broken = true;
        capture_log();
        for _ in 0..MAX_FAILED_POLLS + 2 {
            assert!(failed_with_other(r.poll()));
            assert!(r.cursors.get("nvr1").is_none());
            assert_eq!(r.reader.failed_polls(), 0, "no window to skip yet");
            r.advance(30);
        }
        r.log().broken = false;
        r.log().down = true;
        assert!(failed_with_other(r.poll()));
        assert!(r.cursors.is_empty());
        assert!(problems(&captured_log()).is_empty());

        // the read that works is the first one, from its own time
        r.log().down = false;
        r.advance(30);
        let d = r.device();
        r.add(d - 5, A);
        assert_eq!(r.read(), vec![]);
        assert_eq!(
            logged(
                &captured_log(),
                &format!(
                    "INFO nvr1: first run, watching log entries from {} (device time); 1 log \
                     entry from before the start recorded as already seen, not counted",
                    fmt_ts(d)
                )
            ),
            1
        );
        assert_eq!(r.cursor().since(), d);
    }

    #[test]
    fn an_entry_read_in_overlapping_windows_is_counted_once() {
        let mut r = Run::new();
        let d0 = r.device();
        assert_eq!(r.read(), vec![]);
        r.advance(30);
        r.add(d0 + 10, A);
        // the NVR logged the same entry twice: both are failed logins
        r.add_entry(d0 + 20, B, "0123456789abcdef0123456789abcdef");
        r.add_entry(d0 + 20, B, "0123456789abcdef0123456789abcdef");
        match r.poll() {
            Poll::Read(logins) => {
                let logins: Vec<Login> = logins.collect();
                let host = |ts: i64| ts - SKEW;
                assert_eq!(
                    logins,
                    vec![
                        Login {
                            nvr: "nvr1".to_string(),
                            ip: A.parse().unwrap(),
                            user: "admin".to_string(),
                            at: host(d0 + 10),
                        },
                        Login {
                            nvr: "nvr1".to_string(),
                            ip: B.parse().unwrap(),
                            user: "admin".to_string(),
                            at: host(d0 + 20),
                        },
                        Login {
                            nvr: "nvr1".to_string(),
                            ip: B.parse().unwrap(),
                            user: "admin".to_string(),
                            at: host(d0 + 20),
                        },
                    ]
                );
            }
            _ => panic!("not read"),
        }
        for _ in 0..3 {
            r.advance(30);
            assert_eq!(r.read(), vec![], "read again in the overlap");
        }
        // a third copy of that entry is new
        r.add_entry(d0 + 20, B, "0123456789abcdef0123456789abcdef");
        r.advance(30);
        assert_eq!(r.read(), vec![(B.to_string(), d0 + 20 - SKEW)]);
    }

    #[test]
    fn clock_changes_up_to_clock_jump_are_taken_as_they_are() {
        // a cursor of a quiet NVR trails its clock by findtime + lookback
        let mut r = Run::with_findtime(3600);
        assert_eq!(r.read(), vec![]);
        capture_log();
        // forward by exactly CLOCK_JUMP
        r.advance(30);
        r.log().skew = SKEW + CLOCK_JUMP;
        let d = r.device();
        r.add(d - 5, A);
        assert_eq!(r.read(), vec![(A.to_string(), d - 5 - SKEW - CLOCK_JUMP)]);
        assert_eq!(r.cursor().offset(), Some(SKEW + CLOCK_JUMP));
        assert_eq!(r.cursor().since(), d - 5);
        // back by CLOCK_JUMP on a quiet NVR, whose cursor trails the clock
        r.advance(4000);
        assert_eq!(r.read(), vec![]);
        assert_eq!(r.cursor().since(), r.device() - 3600 - LOOKBACK);
        r.advance(30);
        r.log().skew = SKEW;
        let d = r.device();
        r.add(d - 5, B);
        assert_eq!(r.read(), vec![(B.to_string(), d - 5 - SKEW)]);
        assert_eq!(r.cursor().offset(), Some(SKEW));
        let log = captured_log();
        assert!(problems(&log).is_empty(), "{:?}", log);
        assert!(!log.iter().any(|l| l.contains("recorded as already seen")));
    }

    #[test]
    fn clock_changes_of_more_than_clock_jump_resync() {
        let mut r = Run::with_findtime(3600);
        assert_eq!(r.read(), vec![]);
        // forward
        r.advance(30);
        r.log().skew = SKEW + CLOCK_JUMP + 1;
        let d = r.device();
        r.add(d - 5, A); // logged before the poll that sees the jump
        capture_log();
        assert_eq!(r.read(), vec![]);
        let log = captured_log();
        assert_eq!(
            logged(
                &log,
                &format!(
                    "WARNING nvr1: device clock jumped forward by {} s (to {}); reading on \
                     from the new time, entries already in the log are not counted",
                    CLOCK_JUMP + 1,
                    fmt_ts(d)
                )
            ),
            1,
            "{:?}",
            log
        );
        assert_eq!(
            logged(
                &log,
                "INFO nvr1: 1 existing log entry recorded as already seen"
            ),
            1
        );
        assert_eq!(r.searches().last(), Some(&(d - LOOKBACK, d + 86400)));
        assert_eq!(r.cursor().since(), d);
        assert_eq!(r.cursor().offset(), Some(SKEW + CLOCK_JUMP + 1));
        // after the resync failed logins count again
        r.advance(30);
        let d = r.device();
        r.add(d - 5, A);
        assert_eq!(
            r.read(),
            vec![(A.to_string(), d - 5 - SKEW - CLOCK_JUMP - 1)]
        );

        // back, on a quiet NVR (its cursor trails the clock by more)
        r.advance(4000);
        assert_eq!(r.read(), vec![]);
        r.advance(30);
        r.log().skew = SKEW;
        let d = r.device();
        r.add(d - 5, B);
        assert_eq!(r.read(), vec![]);
        assert_eq!(
            logged(
                &captured_log(),
                &format!(
                    "WARNING nvr1: device clock jumped back by {} s (to {}); reading on from \
                     the new time, entries already in the log are not counted",
                    CLOCK_JUMP + 1,
                    fmt_ts(d)
                )
            ),
            1
        );
        assert_eq!(r.cursor().since(), d);
        assert_eq!(r.cursor().offset(), Some(SKEW));
    }

    #[test]
    fn a_step_back_behind_the_cursor_resyncs_whatever_its_size() {
        let mut r = Run::new();
        assert_eq!(r.read(), vec![]);
        r.advance(30);
        let d = r.device();
        r.add(d, A);
        assert_eq!(r.read(), vec![(A.to_string(), d - SKEW)]);
        assert_eq!(r.cursor().since(), d);
        // 30 s later the device clock shows 10 s earlier than at that read
        r.advance(30);
        r.log().skew = SKEW - 40;
        let back = r.device();
        assert_eq!(back, d - 10);
        r.add(back - 5, B);
        capture_log();
        assert_eq!(r.read(), vec![]);
        assert_eq!(
            logged(
                &captured_log(),
                &format!(
                    "WARNING nvr1: device clock went back from {} to {}; reading on from the new \
                     time, entries already in the log are not counted",
                    fmt_ts(d),
                    fmt_ts(back)
                )
            ),
            1
        );
        assert_eq!(r.cursor().since(), back);
        assert_eq!(r.cursor().offset(), Some(SKEW - 40));
        // the entry at the cursor is not counted again either
        r.advance(30);
        assert_eq!(r.read(), vec![]);
    }

    #[test]
    fn daylight_saving_time_changes_resync_in_both_directions() {
        let mut r = Run::new();
        assert_eq!(r.read(), vec![]);
        r.advance(30);
        let d = r.device();
        r.add(d - 5, A);
        assert_eq!(r.read(), vec![(A.to_string(), d - 5 - SKEW)]);

        // spring: 02:00 becomes 03:00
        r.advance(30);
        r.log().skew = SKEW + 3600;
        let d = r.device();
        capture_log();
        assert_eq!(r.read(), vec![]);
        let log = captured_log();
        assert_eq!(
            logged(
                &log,
                &format!(
                    "WARNING nvr1: device clock jumped forward by 3600 s (to {}); reading on \
                     from the new time, entries already in the log are not counted",
                    fmt_ts(d)
                )
            ),
            1,
            "{:?}",
            log
        );
        r.advance(30);
        let d = r.device();
        r.add(d - 5, B);
        assert_eq!(r.read(), vec![(B.to_string(), d - 5 - SKEW - 3600)]);

        // autumn: 03:00 becomes 02:00, the hour is repeated
        r.advance(30);
        let was = r.cursor().since();
        r.log().skew = SKEW;
        let d = r.device();
        // logged in the repeated hour before the poll that sees the change
        r.add(d - 5, A);
        assert_eq!(r.read(), vec![]);
        assert_eq!(
            logged(
                &captured_log(),
                &format!(
                    "WARNING nvr1: device clock went back from {} to {}; reading on from the new \
                     time, entries already in the log are not counted",
                    fmt_ts(was),
                    fmt_ts(d)
                )
            ),
            1
        );
        assert_eq!(r.cursor().offset(), Some(SKEW));
        // the device times of the repeated hour count once, in host time
        for _ in 0..4 {
            r.advance(30);
            let d = r.device();
            r.add(d - 5, A);
            assert_eq!(r.read(), vec![(A.to_string(), d - 5 - SKEW)]);
        }
    }

    #[test]
    fn a_clock_change_while_the_log_cannot_be_read_resyncs_after_the_skip() {
        let mut r = Run::new();
        assert_eq!(r.read(), vec![]);
        r.advance(30);
        let d = r.device();
        r.add(d - 5, A);
        assert_eq!(r.read(), vec![(A.to_string(), d - 5 - SKEW)]);
        let since = r.cursor().since();

        // the device clock goes back an hour, and every search fails
        r.log().skew = SKEW - 3600;
        r.log().broken = true;
        capture_log();
        for i in 1..MAX_FAILED_POLLS {
            r.advance(30);
            assert!(failed_with_other(r.poll()));
            assert_eq!(r.reader.failed_polls(), i);
            assert_eq!(r.cursor().since(), since);
            assert_eq!(r.cursor().offset(), Some(SKEW));
        }
        let log = captured_log();
        assert_eq!(
            log.iter()
                .filter(|l| l.contains("device clock went back from"))
                .count(),
            9,
            "{:?}",
            log
        );
        r.advance(30);
        let d = r.device();
        assert!(failed_with_other(r.poll()));
        let log = captured_log();
        assert_eq!(
            logged(
                &log,
                &format!(
                    "ERROR nvr1: the log could not be read 10 times in a row; SKIPPING the log \
                     window {} .. {} (device time), failed logins in it are not counted; the \
                     device clock changed, so the next read records the log as already seen",
                    fmt_ts(d - LOOKBACK),
                    fmt_ts(d)
                )
            ),
            1,
            "{:?}",
            log
        );
        assert_eq!(r.cursor().since(), d);
        assert_eq!(r.cursor().offset(), None, "a resync is still due");
        assert_eq!(r.reader.failed_polls(), 0);

        // the next read that works resyncs
        r.log().broken = false;
        r.advance(30);
        let d = r.device();
        r.add(d - 5, B); // logged at a device time of the repeated hour
        assert_eq!(r.read(), vec![]);
        let log = captured_log();
        assert_eq!(
            logged(
                &log,
                &format!(
                    "WARNING nvr1: no device clock offset is known (the read position was moved \
                     to {} without a read); reading on from the new time, entries already in \
                     the log are not counted",
                    fmt_ts(d - 30)
                )
            ),
            1,
            "{:?}",
            log
        );
        assert_eq!(r.cursor().offset(), Some(SKEW - 3600));
        r.advance(30);
        let d = r.device();
        r.add(d - 5, B);
        assert_eq!(r.read(), vec![(B.to_string(), d - 5 - SKEW + 3600)]);
    }

    #[test]
    fn an_unknown_offset_in_the_state_file_forces_a_resync() {
        let mut r = Run::new();
        let d = r.device();
        r.cursors = State::parse(&format!("hik-f2b-state 2\nnvr nvr1 {} -\n", d - 30)).cursors;
        assert_eq!(r.cursor().offset(), None);
        r.add(d - 10, A);
        capture_log();
        assert_eq!(r.read(), vec![]);
        let log = captured_log();
        assert_eq!(
            logged(
                &log,
                &format!(
                    "WARNING nvr1: no device clock offset is known (the read position was moved \
                     to {} without a read); reading on from the new time, entries already in \
                     the log are not counted",
                    fmt_ts(d - 30)
                )
            ),
            1,
            "{:?}",
            log
        );
        assert_eq!(
            logged(
                &log,
                "INFO nvr1: 1 existing log entry recorded as already seen"
            ),
            1
        );
        assert_eq!(r.searches(), vec![(d - LOOKBACK, d + 86400)]);
        assert_eq!(r.cursor().since(), d);
        assert_eq!(r.cursor().offset(), Some(SKEW));
    }

    #[test]
    fn a_log_window_that_cannot_be_read_is_skipped_after_ten_polls() {
        let mut r = Run::new();
        let d0 = r.device();
        assert_eq!(r.read(), vec![]);
        r.log().broken = true;
        capture_log();
        for i in 1..MAX_FAILED_POLLS {
            r.advance(30);
            assert!(failed_with_other(r.poll()));
            assert_eq!(r.reader.failed_polls(), i);
            assert_eq!(r.cursor().since(), d0);
        }
        assert!(problems(&captured_log()).is_empty());
        r.add(d0 + 100, A); // in the window that will be skipped
        r.advance(30);
        let d = r.device();
        assert!(failed_with_other(r.poll()));
        let log = captured_log();
        assert_eq!(
            problems(&log),
            vec![&format!(
                "ERROR nvr1: the log could not be read 10 times in a row; SKIPPING the log \
                 window {} .. {} (device time), failed logins in it are not counted",
                fmt_ts(d0 - LOOKBACK),
                fmt_ts(d)
            )]
        );
        assert_eq!(r.cursor().since(), d);
        // the clock did not change: no resync, so what follows is counted
        assert_eq!(r.cursor().offset(), Some(SKEW));
        assert_eq!(r.reader.failed_polls(), 0);
        assert_eq!(r.reader.retry_after(), 0, "not a login problem");

        r.log().broken = false;
        r.advance(30);
        let d = r.device();
        r.add(d - 5, B);
        assert_eq!(r.read(), vec![(B.to_string(), d - 5 - SKEW)]);
        assert_eq!(r.searches().last(), Some(&(d - 30 - LOOKBACK, d + 86400)));
    }

    #[test]
    fn an_nvr_that_cannot_be_reached_does_not_count_towards_skipping() {
        let mut r = Run::new();
        let d0 = r.device();
        assert_eq!(r.read(), vec![]);
        r.log().down = true;
        for _ in 0..3 * MAX_FAILED_POLLS {
            r.advance(30);
            assert!(failed_with_other(r.poll()));
            assert_eq!(r.reader.failed_polls(), 0);
        }
        assert_eq!(r.cursor().since(), d0);
        assert_eq!(r.searches().len(), 1, "only the first poll searched");
        // after 9 polls that could not read the log, 1 that could not reach
        // the NVR does not make 10
        r.log().down = false;
        r.log().broken = true;
        for _ in 1..MAX_FAILED_POLLS {
            r.advance(30);
            assert!(failed_with_other(r.poll()));
        }
        r.log().down = true;
        r.advance(30);
        assert!(failed_with_other(r.poll()));
        assert_eq!(r.reader.failed_polls(), MAX_FAILED_POLLS - 1);
        assert_eq!(r.cursor().since(), d0);
    }

    #[test]
    fn a_rejected_login_backs_off_for_auth_backoff() {
        let mut r = Run::new();
        r.log().refuse = true;
        assert!(matches!(r.poll(), Poll::Failed(NvrError::Auth(_))));
        assert_eq!(r.reader.retry_after(), H0 + AUTH_BACKOFF);
        assert_eq!(r.log().time_requests, 1);
        r.log().refuse = false;
        // not contacted until auth_backoff has passed
        r.advance(AUTH_BACKOFF - 1);
        assert!(matches!(r.poll(), Poll::BackingOff));
        assert_eq!(r.log().time_requests, 1);
        r.advance(1);
        assert_eq!(r.read(), vec![]);
        assert_eq!(r.log().time_requests, 2);
        assert!(r.cursors.get("nvr1").is_some());

        // a failed read that is not a login problem does not back off
        r.log().broken = true;
        r.advance(30);
        assert!(failed_with_other(r.poll()));
        r.advance(30);
        assert!(failed_with_other(r.poll()));
        assert_eq!(r.log().time_requests, 4);
        assert_eq!(r.reader.retry_after(), H0 + AUTH_BACKOFF, "not set again");
    }

    #[test]
    fn a_host_clock_that_went_back_does_not_stall_the_backoff() {
        let mut r = Run::new();
        r.log().refuse = true;
        assert!(matches!(r.poll(), Poll::Failed(NvrError::Auth(_))));
        r.log().refuse = false;
        // the host clock is set back a year; the device clock stays right
        r.host -= 365 * 86400;
        r.log().skew = SKEW + 365 * 86400;
        assert_eq!(r.read(), vec![]);
        assert_eq!(r.reader.retry_after(), 0);
        assert_eq!(r.log().time_requests, 2);
        // a wait of exactly auth_backoff is kept
        r.log().refuse = true;
        assert!(matches!(r.poll(), Poll::Failed(NvrError::Auth(_))));
        assert!(matches!(r.poll(), Poll::BackingOff));
    }

    #[test]
    fn an_nvr_that_lists_oldest_first_is_read_on_from_the_newest_entry_read() {
        let mut r = Run::new();
        r.log().per_search = 5;
        let d0 = r.device();
        assert_eq!(r.read(), vec![]);
        for i in [1, 2, 3, 200, 201, 202, 203, 204] {
            r.add(d0 + i, A);
        }
        r.searches();
        r.advance(300);
        let host = |i: i64| (A.to_string(), d0 + i - SKEW);
        assert_eq!(
            r.read(),
            [1, 2, 3, 200, 201].map(host).to_vec(),
            "the start of the window"
        );
        assert_eq!(r.searches().len(), 1, "the rest is newer: read next time");
        assert_eq!(r.cursor().since(), d0 + 201);
        assert_eq!(r.cursor().seen(), 5);
        r.advance(30);
        assert_eq!(r.read(), [202, 203, 204].map(host).to_vec());
        assert_eq!(r.searches(), vec![(d0 + 201 - LOOKBACK, d0 + 330 + 86400)]);
        assert_eq!(r.cursor().since(), d0 + 204);
        r.advance(30);
        assert_eq!(r.read(), vec![]);
    }

    #[test]
    fn an_nvr_that_lists_newest_first_is_read_to_the_start_of_the_window() {
        let mut r = Run::new();
        r.log().per_search = 5;
        r.log().newest_first = true;
        let d0 = r.device();
        assert_eq!(r.read(), vec![]);
        for i in 1..=12 {
            r.add(d0 + i, A);
        }
        r.searches();
        r.advance(30);
        capture_log();
        let mut read = r.read();
        read.sort();
        let mut all: Vec<_> = (1..=12).map(|i| (A.to_string(), d0 + i - SKEW)).collect();
        all.sort();
        assert_eq!(read, all, "each entry once");
        // each search ends just after the oldest second read so far
        let start = d0 - LOOKBACK;
        assert_eq!(
            r.searches(),
            vec![
                (start, d0 + 30 + 86400),
                (start, d0 + 9),
                (start, d0 + 6),
                (start, d0 + 3)
            ]
        );
        assert!(problems(&captured_log()).is_empty());
        assert_eq!(r.cursor().since(), d0 + 12);
        assert_eq!(r.cursor().seen(), 12);
        r.advance(30);
        assert_eq!(r.read(), vec![]);
    }

    #[test]
    fn the_searches_of_one_poll_are_capped() {
        let mut r = Run::new();
        r.log().per_search = 5;
        r.log().newest_first = true;
        let d0 = r.device();
        assert_eq!(r.read(), vec![]);
        for i in 1..=20 {
            r.add(d0 + i, A);
        }
        r.searches();
        r.advance(30);
        capture_log();
        let mut read = r.read();
        read.sort();
        let mut want: Vec<_> = (8..=20).map(|i| (A.to_string(), d0 + i - SKEW)).collect();
        want.sort();
        assert_eq!(read, want);
        assert_eq!(r.searches().len(), MAX_SEARCHES);
        assert_eq!(
            problems(&captured_log()),
            vec![&format!(
                "ERROR nvr1: not every log entry in {} .. {} (device time) could be read with \
                 4 searches in one poll; SKIPPING the rest of it, failed logins in it are not \
                 counted",
                fmt_ts(d0 - LOOKBACK),
                fmt_ts(d0 + 7)
            )]
        );
        assert_eq!(r.cursor().since(), d0 + 20);
    }

    #[test]
    fn more_entries_in_one_second_than_one_search_returns() {
        let mut r = Run::new();
        r.log().per_search = 5;
        let d0 = r.device();
        assert_eq!(r.read(), vec![]);
        for _ in 0..7 {
            r.add(d0 + 5, A);
        }
        r.searches();
        r.advance(30);
        capture_log();
        assert_eq!(r.read(), vec![(A.to_string(), d0 + 5 - SKEW); 5]);
        // the order cannot be told: the time before that second is read too
        let start = d0 - LOOKBACK;
        assert_eq!(
            r.searches(),
            vec![(start, d0 + 30 + 86400), (start, d0 + 4)]
        );
        assert!(problems(&captured_log()).is_empty());
        assert_eq!(r.cursor().since(), d0 + 5);
        // the same five again: nothing new, and the cursor moves on by one
        // second
        r.advance(30);
        assert_eq!(r.read(), vec![]);
        assert_eq!(
            problems(&captured_log()),
            vec![
                "WARNING nvr1: more log entries within one second than can be read in one \
                 poll; moving on by one second, some entries may have been skipped"
            ]
        );
        assert_eq!(r.cursor().since(), d0 + 6);
        assert_eq!(r.cursor().seen(), 5);
    }

    #[test]
    fn seen_entries_are_kept_after_a_cut_up_to_max_seen() {
        let mut r = Run::new();
        r.log().per_search = 5;
        let d0 = r.device();
        assert_eq!(r.read(), vec![]);
        for i in 1..=8 {
            r.add(d0 + i, A);
        }
        r.advance(30);
        assert_eq!(r.read().len(), 5);
        // the first five stay known while the rest is read
        r.log().per_search = 3;
        r.advance(30);
        assert_eq!(r.read(), vec![]);
        assert_eq!(r.cursor().seen(), 5);
        r.log().per_search = 100;
        r.advance(30);
        assert_eq!(r.read().len(), 3);
        assert_eq!(r.cursor().seen(), 8);

        // a cursor that holds MAX_SEEN entries keeps only the window read
        let d = r.device();
        let mut text = format!("hik-f2b-state 2\nnvr nvr1 {} {}\n", d - 30, SKEW);
        for i in 0..MAX_SEEN {
            text.push_str(&format!("seen nvr1 {:032x} 1\n", u128::MAX - i as u128));
        }
        r.cursors = State::parse(&text).cursors;
        assert_eq!(r.cursor().seen(), MAX_SEEN);
        r.log().entries.clear();
        r.log().per_search = 2;
        r.add(d - 10, B);
        r.add(d - 9, B);
        r.add(d - 8, B);
        r.advance(30);
        assert_eq!(r.read().len(), 2);
        assert_eq!(r.cursor().seen(), 2);
    }

    #[test]
    fn the_counting_window_is_findtime_back_and_max_future_ahead() {
        let mut r = Run::new();
        assert_eq!(r.read(), vec![]);
        // a quiet NVR: the window starts at findtime + lookback back
        r.advance(1000);
        let h = r.host as i64;
        let d = r.device();
        for t in [
            h - FINDTIME - 1,
            h - FINDTIME,
            h + MAX_FUTURE,
            h + MAX_FUTURE + 1,
        ] {
            r.add(t + SKEW, A);
        }
        r.searches();
        capture_log();
        assert_eq!(
            r.read(),
            vec![
                (A.to_string(), h - FINDTIME),
                (A.to_string(), h + MAX_FUTURE)
            ]
        );
        let horizon = d - FINDTIME - LOOKBACK;
        assert_eq!(r.searches(), vec![(horizon - LOOKBACK, d + 86400)]);
        let outside = |t: i64| {
            format!(
                "DEBUG nvr1: entry at {} (device time) is outside the counting window, not \
                 counted",
                fmt_ts(t + SKEW)
            )
        };
        let log = captured_log();
        assert_eq!(
            log,
            vec![
                format!(
                    "DEBUG nvr1: skipping log entries before {} (older than findtime)",
                    fmt_ts(horizon)
                ),
                outside(h - FINDTIME - 1),
                outside(h + MAX_FUTURE + 1),
            ]
        );
        // the cursor never runs ahead of the device clock
        assert_eq!(r.cursor().since(), d);
    }

    #[test]
    fn entries_without_a_time_or_an_address_or_of_another_kind_are_not_counted() {
        let mut r = Run::new();
        let d0 = r.device();
        assert_eq!(r.read(), vec![]);
        r.add(d0 + 1, A);
        let entries = &mut r.log().entries;
        entries[0].meta = "login".to_string(); // not matched by log_filter
        let mut no_address = entries[0].clone();
        no_address.meta = "illegalLogin".to_string();
        no_address.ip = None;
        no_address.key = format!("{:032x}", 99);
        entries.push(no_address);
        r.advance(30);
        capture_log();
        assert_eq!(r.read(), vec![]);
        assert_eq!(
            captured_log(),
            vec!["DEBUG nvr1: entry without time or address skipped"]
        );
    }

    #[test]
    fn a_cursor_is_the_same_after_a_save_and_a_load() {
        let mut r = Run::new();
        r.log().per_search = 5;
        let d0 = r.device();
        assert_eq!(r.read(), vec![]);
        for i in 1..=8 {
            r.add(d0 + i, A);
        }
        r.advance(30);
        assert_eq!(r.read().len(), 5);
        let state = State {
            cursors: r.cursors.clone(),
            ..Default::default()
        };
        let text = state.serialize();
        let loaded = State::parse(&text).cursors;
        assert_eq!(loaded, r.cursors);
        assert_eq!(State::parse(&text).serialize(), text);
        // a reader that goes on from the loaded cursors counts nothing twice
        r.cursors = loaded;
        r.log().per_search = 100;
        r.advance(30);
        assert_eq!(r.read().len(), 3);

        // a resync that is due survives too
        let text = format!("hik-f2b-state 2\nnvr nvr1 {} -\n", d0);
        let cursors = State::parse(&text).cursors;
        assert_eq!(cursors["nvr1"].offset(), None);
        assert_eq!(
            State {
                cursors,
                ..Default::default()
            }
            .serialize(),
            text
        );
    }

    /// The WARNING of a resync whose read was cut, for a window from
    /// `start` (device time); `first`: on the first poll.
    fn cut(first: bool, start: i64) -> String {
        format!(
            "WARNING nvr1: {}the log holds more entries from {} (device time) on than one \
             read returns, so not all of them can be recorded as already seen; failed logins \
             of this NVR are not counted until the log can be read whole",
            if first { "first run: " } else { "" },
            fmt_ts(start)
        )
    }

    #[test]
    fn a_resync_after_a_step_back_stays_due_while_its_read_is_cut() {
        let mut r = Run::new();
        let d0 = r.device();
        assert_eq!(r.read(), vec![]);
        // 20 s apart: an overlap holds fewer than one search returns
        let old: Vec<i64> = (1..=25).map(|i| d0 + 20 * i).collect();
        for &t in &old {
            r.add(t, A);
        }
        r.advance(520);
        assert_eq!(r.read().len(), 25, "counted before the change");
        // from now on one search returns 10 entries; the clock goes back an
        // hour, so the 25 lie ahead of the new time
        r.log().per_search = 10;
        r.advance(30);
        r.log().skew = SKEW - 3600;
        let back = r.device();
        capture_log();
        assert_eq!(r.read(), vec![]);
        let log = captured_log();
        let (mut counted, _) = r.read_on(20);
        // a failed login logged during the resync is not counted either
        let d = r.device();
        r.add(d - 5, B);
        let (more, done) = r.read_on(130);
        counted.extend(more);
        assert_eq!(
            counted,
            vec![],
            "nothing from before the change, or during the resync"
        );
        // complete at the first poll whose window holds 10 entries at most
        let in_window = |t: i64| old.iter().filter(|&&e| e >= t - LOOKBACK).count();
        let first_whole = (1..)
            .map(|k| back + 30 * k)
            .find(|&t| in_window(t) <= 10)
            .unwrap();
        assert_eq!(done, Some(first_whole));
        assert_eq!(
            problems(&log),
            vec![
                &format!(
                    "WARNING nvr1: device clock went back from {} to {}; reading on from the new \
                     time, entries already in the log are not counted",
                    fmt_ts(d0 + 500),
                    fmt_ts(back)
                ),
                &cut(false, back - LOOKBACK)
            ]
        );
        let log = captured_log();
        assert!(problems(&log).is_empty(), "said once: {:?}", problems(&log));
        assert_eq!(
            log.iter()
                .filter(|l| l.starts_with("INFO") && l.contains("recorded as already seen"))
                .collect::<Vec<_>>(),
            vec![&format!(
                "INFO nvr1: {} existing log entries recorded as already seen",
                in_window(first_whole)
            )]
        );
        assert_eq!(r.cursor().offset(), Some(SKEW - 3600));
        // after the resync failed logins count again
        r.advance(30);
        let d = r.device();
        r.add(d - 5, B);
        assert_eq!(r.read(), vec![(B.to_string(), d - 5 - SKEW + 3600)]);
        let (counted, _) = r.read_on(10);
        assert_eq!(counted, vec![]);
    }

    #[test]
    fn a_cut_resync_keeps_the_offset_unknown_in_the_cursor() {
        let mut r = Run::new();
        let d0 = r.device();
        assert_eq!(r.read(), vec![]);
        for i in 1..=25 {
            r.add(d0 + i, A);
        }
        r.advance(30);
        assert_eq!(r.read().len(), 25);
        r.log().per_search = 10;
        r.advance(30);
        r.log().skew = SKEW - 3600;
        let back = r.device();
        assert_eq!(r.read(), vec![]);
        assert_eq!(r.cursor().offset(), None, "the resync is still due");
        assert_eq!(r.cursor().since(), back);
        assert_eq!(r.cursor().seen(), 10, "what was read");
        r.searches();
        r.advance(30);
        assert_eq!(r.read(), vec![]);
        assert_eq!(
            r.searches(),
            vec![(back + 30 - LOOKBACK, back + 30 + 86400)],
            "from its own time"
        );
        assert_eq!(r.cursor().offset(), None);
        assert_eq!(r.cursor().since(), back + 30);
    }

    #[test]
    fn a_resync_after_a_jump_forward_stays_due_while_its_read_is_cut() {
        let mut r = Run::with_findtime(3600);
        assert_eq!(r.read(), vec![]);
        r.log().per_search = 10;
        r.advance(30);
        r.log().skew = SKEW + 3600;
        let d = r.device();
        // logged after the jump, before the poll that sees it: 15 in the
        // lookback before it
        for j in 0..15 {
            r.add(d - 118 + 8 * j, A);
        }
        capture_log();
        assert_eq!(r.read(), vec![]);
        let (counted, done) = r.read_on(100);
        assert_eq!(counted, vec![], "entries already in the log at the change");
        // 11 entries from d - 90 on, 7 from d - 60 on
        assert_eq!(done, Some(d + 60));
        let log = captured_log();
        assert_eq!(
            problems(&log),
            vec![
                &format!(
                    "WARNING nvr1: device clock jumped forward by 3600 s (to {}); reading on \
                     from the new time, entries already in the log are not counted",
                    fmt_ts(d)
                ),
                &cut(false, d - LOOKBACK)
            ]
        );
        assert_eq!(
            logged(
                &log,
                "INFO nvr1: 7 existing log entries recorded as already seen"
            ),
            1
        );
        r.advance(30);
        let d = r.device();
        r.add(d - 5, B);
        assert_eq!(r.read(), vec![(B.to_string(), d - 5 - SKEW - 3600)]);
    }

    #[test]
    fn a_first_poll_whose_read_is_cut_leaves_the_nvr_unknown() {
        let mut r = Run::with_findtime(3600);
        r.log().per_search = 10;
        let d0 = r.device();
        for j in 0..15 {
            r.add(d0 - 118 + 8 * j, A);
        }
        capture_log();
        assert_eq!(r.read(), vec![]);
        let unknown = r.cursors.get("nvr1").is_none();
        let (counted, done) = r.read_on(100);
        assert_eq!(counted, vec![], "entries from before the start");
        assert!(unknown, "the next poll is a first poll again");
        assert_eq!(done, Some(d0 + 60));
        let log = captured_log();
        assert_eq!(problems(&log), vec![&cut(true, d0 - LOOKBACK)]);
        assert_eq!(
            log.iter()
                .filter(|l| l.starts_with("INFO") && l.contains("recorded as already seen"))
                .collect::<Vec<_>>(),
            vec![&format!(
                "INFO nvr1: first run, watching log entries from {} (device time); 7 log \
                 entries from before the start recorded as already seen, not counted",
                fmt_ts(d0 + 60)
            )]
        );
        r.advance(30);
        let d = r.device();
        r.add(d - 5, B);
        assert_eq!(r.read(), vec![(B.to_string(), d - 5 - SKEW)]);
    }

    #[test]
    fn a_resync_cut_within_one_second_stays_due() {
        // the cursor stays at that second for two minutes before the entries
        // after it are read
        let mut r = Run::with_findtime(7200);
        let d0 = r.device();
        assert_eq!(r.read(), vec![]);
        for _ in 0..7 {
            r.add(d0 + 5, A);
        }
        for i in 4..=7 {
            r.add(d0 + 10 * i, A);
        }
        r.advance(90);
        assert_eq!(r.read().len(), 11, "counted before the change");
        // the first search of the resync returns 5 entries of one second
        r.log().per_search = 5;
        r.advance(30);
        r.log().skew = SKEW - 3600;
        let back = r.device();
        capture_log();
        assert_eq!(r.read(), vec![]);
        let (counted, done) = r.read_on(260);
        assert_eq!(counted, vec![], "nothing from before the change");
        // complete once that second has left the window
        let first_whole = back + (d0 + 6 + LOOKBACK - back + 29) / 30 * 30;
        assert_eq!(done, Some(first_whole));
        let log = captured_log();
        assert_eq!(problems(&log)[1..], [&cut(false, back - LOOKBACK)]);
        assert_eq!(
            logged(
                &log,
                "INFO nvr1: 4 existing log entries recorded as already seen"
            ),
            1
        );
    }

    #[test]
    fn a_resync_of_an_nvr_that_lists_newest_first_stays_due_while_its_read_is_cut() {
        let mut r = Run::new();
        r.log().newest_first = true;
        let d0 = r.device();
        assert_eq!(r.read(), vec![]);
        let old: Vec<i64> = (1..=30).map(|i| d0 + 4 * i).collect();
        for &t in &old {
            r.add(t, A);
        }
        r.advance(150);
        assert_eq!(r.read().len(), 30, "counted before the change");
        // four searches of 5 read the newest 17 entries, d0 + 60 ..= 120
        r.log().per_search = 5;
        r.advance(30);
        r.log().skew = SKEW - 3600;
        let back = r.device();
        capture_log();
        assert_eq!(r.read(), vec![]);
        let log = captured_log();
        let (counted, done) = r.read_on(130);
        assert_eq!(counted, vec![], "nothing from before the change");
        assert_eq!(
            problems(&log)[1..],
            [
                &format!(
                    "ERROR nvr1: not every log entry in {} .. {} (device time) could be read \
                     with 4 searches in one poll; SKIPPING the rest of it, failed logins in it \
                     are not counted",
                    fmt_ts(back - LOOKBACK),
                    fmt_ts(d0 + 56)
                ),
                &cut(false, back - LOOKBACK)
            ]
        );
        // complete once the fourth search reads to the start of the window:
        // at most 5 entries up to d0 + 56 in it
        let first_whole = (1..)
            .map(|k| back + 30 * k)
            .find(|&t| t - LOOKBACK > d0 + 36)
            .unwrap();
        assert_eq!(done, Some(first_whole));
        let log = captured_log();
        assert!(
            !log.iter().any(|l| l.contains("can be read whole")),
            "said once"
        );
        let left = old.iter().filter(|&&e| e >= first_whole - LOOKBACK).count();
        assert_eq!(
            logged(
                &log,
                &format!(
                    "INFO nvr1: {} existing log entries recorded as already seen",
                    left
                )
            ),
            1
        );
    }

    #[test]
    fn a_cut_resync_of_an_nvr_that_turns_to_oldest_first_counts_nothing_from_before_it() {
        // newest first, the older part of the window is not read; an NVR
        // that lists oldest first from then on reads it first
        let mut r = Run::with_findtime(3600);
        r.log().newest_first = true;
        let d0 = r.device();
        assert_eq!(r.read(), vec![]);
        // 40 s apart: an overlap holds fewer than one search returns
        for i in 1..=30 {
            r.add(d0 + 40 * i, A);
        }
        r.advance(1230);
        assert_eq!(r.read().len(), 30, "counted before the change");
        r.log().per_search = 5;
        r.advance(30);
        r.log().skew = SKEW - 3600;
        assert_eq!(r.read(), vec![]);
        r.log().newest_first = false;
        let (counted, done) = r.read_on(130);
        assert_eq!(counted, vec![], "nothing from before the change");
        assert!(done.is_some());
    }

    #[test]
    fn a_cut_resync_survives_a_save_and_a_load_and_a_restart() {
        let mut r = Run::new();
        let d0 = r.device();
        assert_eq!(r.read(), vec![]);
        for i in 1..=25 {
            r.add(d0 + i, A);
        }
        r.advance(30);
        assert_eq!(r.read().len(), 25);
        r.log().per_search = 10;
        r.advance(30);
        r.log().skew = SKEW - 3600;
        let back = r.device();
        assert_eq!(r.read(), vec![]);
        // the state file holds it in the format of 0.5.1: an unknown offset
        let text = State {
            cursors: r.cursors.clone(),
            ..Default::default()
        }
        .serialize();
        assert!(
            text.starts_with(&format!("hik-f2b-state 2\nnvr nvr1 {} -\nseen nvr1 ", back)),
            "{}",
            text
        );
        assert_eq!(text.lines().count(), 2 + 10);
        let loaded = State::parse(&text).cursors;
        assert_eq!(loaded, r.cursors);
        assert_eq!(State::parse(&text).serialize(), text);
        r.cursors = loaded;
        r.restart();
        capture_log();
        r.advance(30);
        assert_eq!(r.read(), vec![]);
        assert_eq!(r.cursor().offset(), None, "still due after the restart");
        // after a restart hik-f2b cannot tell why the resync is due: it says
        // the reason the state file gives, and the cut once more
        assert_eq!(
            problems(&captured_log()),
            vec![
                &format!(
                    "WARNING nvr1: no device clock offset is known (the read position was moved \
                     to {} without a read); reading on from the new time, entries already in \
                     the log are not counted",
                    fmt_ts(back)
                ),
                &cut(false, back + 30 - LOOKBACK)
            ]
        );
        let (counted, done) = r.read_on(130);
        assert_eq!(counted, vec![]);
        assert!(done.is_some());
        assert!(problems(&captured_log()).is_empty());
    }

    #[test]
    fn a_skipped_window_during_a_cut_resync_says_why_the_next_one_is_due() {
        let mut r = Run::new();
        let d0 = r.device();
        assert_eq!(r.read(), vec![]);
        for i in 1..=25 {
            r.add(d0 + i, A);
        }
        r.advance(30);
        assert_eq!(r.read().len(), 25);
        r.log().per_search = 10;
        r.advance(30);
        r.log().skew = SKEW - 3600;
        assert_eq!(r.read(), vec![]);
        r.log().broken = true;
        capture_log();
        for _ in 0..MAX_FAILED_POLLS {
            r.advance(30);
            assert!(failed_with_other(r.poll()));
        }
        let moved = r.device();
        assert_eq!(r.cursor().since(), moved);
        assert_eq!(r.cursor().offset(), None);
        r.log().broken = false;
        r.advance(30);
        assert_eq!(r.read(), vec![]);
        let log = captured_log();
        assert_eq!(
            problems(&log)[1..],
            [
                &format!(
                    "WARNING nvr1: no device clock offset is known (the read position was moved \
                     to {} without a read); reading on from the new time, entries already in \
                     the log are not counted",
                    fmt_ts(moved)
                ),
                &cut(false, moved + 30 - LOOKBACK)
            ]
        );
    }
}
