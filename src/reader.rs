//! One NVR log reader per NVR: the rules of reading one NVR's log.
//!
//! The reader owns what reading needs: the client, the read cursor that the
//! state file keeps (`Cursor`: `since`, `offset`, `seen`), the counters kept
//! in memory (failed polls, the login backoff), the rules for a device clock
//! that jumped and for a resync, the search window (order, paging, the
//! caps) and the conversion of device time to host time. It is asked once
//! per poll, at a host time, and answers with the new failed logins in host
//! time inside the counting window, or that it was not tried, or why the
//! read failed. The rest of the engine never sees device time.

use crate::config::Config;
use crate::ledger::MAX_FUTURE;
use crate::nvr::{Event, Nvr, NvrError};
use crate::util::{self, host_i64};
use std::collections::{BTreeMap, HashMap};
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

/// Where one NVR's log was read up to; the state file keeps it.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct Cursor {
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

/// The log reader of one NVR.
pub struct LogReader {
    pub nvr: Nvr,
}

/// What one poll of an NVR gave.
pub enum Poll {
    /// Not tried: the reader backs off after a rejected login.
    BackingOff,
    /// The NVR could not be read: its login was rejected (`NvrError::Auth`,
    /// the reader now backs off) or something else failed.
    Failed(NvrError),
    /// The log was read; these are the new failed logins.
    Read(Logins),
}

/// One new failed login, in host time.
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

impl LogReader {
    pub fn new(nvr: Nvr) -> LogReader {
        LogReader { nvr }
    }

    /// The NVR's name.
    pub fn name(&self) -> &str {
        &self.nvr.name
    }

    /// One poll at host time `host_now`. `cursors` holds the read cursor of
    /// every NVR (the state file's), by name.
    pub fn poll(
        &mut self,
        cursors: &mut BTreeMap<String, Cursor>,
        cfg: &Config,
        host_now: u64,
    ) -> Poll {
        let retry_after = self.nvr.retry_after;
        if retry_after > host_now {
            // A wait longer than auth_backoff can only come from the
            // host clock jumping back; do not wait for years.
            if retry_after - host_now <= cfg.auth_backoff {
                return Poll::BackingOff;
            }
            self.nvr.retry_after = 0;
        }
        let now = host_i64(host_now);
        match poll_nvr(&mut self.nvr, cfg, cursors, now) {
            Err(NvrError::Auth(e)) => {
                self.nvr.retry_after = host_now.saturating_add(cfg.auth_backoff);
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
fn read_window(nvr: &mut Nvr, start: i64, end: i64, meta_id: &str) -> Result<Window, NvrError> {
    let mut window = Window {
        events: Vec::new(),
        newest: None,
        cut_after: false,
    };
    let mut end = end;
    // Entries after this came from an earlier search of this poll.
    let mut keep_to: Option<i64> = None;
    for n in 0..MAX_SEARCHES {
        let search = nvr.search(start, end, meta_id, None)?;
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
                    nvr.name,
                    util::fmt_ts(oldest)
                );
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
            return Ok(window);
        }
    }
    if let Some(to) = keep_to {
        crate::error!(
            "{}: not every log entry in {} .. {} (device time) could be read with {} searches \
             in one poll; SKIPPING the rest of it, failed logins in it are not counted",
            nvr.name,
            util::fmt_ts(start),
            util::fmt_ts(to),
            MAX_SEARCHES
        );
    }
    Ok(window)
}

/// Reads one NVR's log. Owns the read cursor (`since`, device time) and the
/// `seen` set.
///
/// The first poll of an NVR reads from its current time. It records what
/// the `lookback` overlap before that holds as already seen, without
/// counting it, so failed logins from before the start are never counted.
/// Until that read succeeds the NVR stays unknown, and the next poll tries
/// again.
fn poll_nvr(
    nvr: &mut Nvr,
    cfg: &Config,
    cursors: &mut BTreeMap<String, Cursor>,
    host_now: i64,
) -> Result<Polled, NvrError> {
    // An NVR that cannot be reached at all does not count towards skipping
    // a log window (`failed_polls`): only a log that cannot be read does.
    let now = nvr.now()?;
    let offset = now.saturating_sub(host_now);
    let first = !cursors.contains_key(&nvr.name);
    let st = cursors.entry(nvr.name.clone()).or_insert_with(|| Cursor {
        since: now,
        offset: Some(offset),
        ..Default::default()
    });
    let result = read_log(nvr, cfg, st, now, offset, first);
    if first && result.is_err() {
        cursors.remove(&nvr.name);
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
///
/// `since` is never ahead of the device clock, so that the clock going back
/// is noticed at the next poll.
fn read_log(
    nvr: &mut Nvr,
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
    let previous = st.since;
    let mut since = st.since;
    if let Some(jump) = &jump {
        crate::warn!(
            "{}: {}; reading on from the new time, entries already in the log are not counted",
            nvr.name,
            jump
        );
        since = now;
    }
    // Entries older than findtime cannot contribute to a ban; skipping them
    // also avoids reading the whole log history after a long outage.
    let horizon = now.saturating_sub(cfg.findtime.saturating_add(lookback));
    if since < horizon {
        crate::debug!(
            "{}: skipping log entries before {} (older than findtime)",
            nvr.name,
            util::fmt_ts(horizon)
        );
        since = horizon;
    }

    let result = read_window(
        nvr,
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
            nvr.failed_polls = nvr.failed_polls.saturating_add(1);
            if nvr.failed_polls >= MAX_FAILED_POLLS {
                // Without this a single entry the NVR cannot deliver would
                // stop the daemon from ever reading on.
                crate::error!(
                    "{}: the log could not be read {} times in a row; SKIPPING the log window \
                     {} .. {} (device time), failed logins in it are not counted{}",
                    nvr.name,
                    nvr.failed_polls,
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
                // stays due (see above).
                st.offset = if baseline { None } else { Some(offset) };
                nvr.failed_polls = 0;
            }
            return Err(NvrError::Other(e));
        }
        Err(e) => return Err(e),
    };
    nvr.failed_polls = 0;

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
            crate::debug!("{}: entry without time or address skipped", nvr.name);
            continue;
        }
        let n = counter.entry(ev.key.clone()).or_insert(0);
        *n = n.saturating_add(1);
        if !baseline && *n > st.seen.get(&ev.key).copied().unwrap_or(0) {
            fresh.push(ev);
        }
    }
    let entries = if counter.len() == 1 { "y" } else { "ies" };
    if first {
        crate::info!(
            "{}: first run, watching log entries from {} (device time); {} log entr{} from \
             before the start recorded as already seen, not counted",
            nvr.name,
            util::fmt_ts(now),
            counter.len(),
            entries
        );
    } else if baseline {
        crate::info!(
            "{}: {} existing log entr{} recorded as already seen",
            nvr.name,
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
                nvr.name
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
