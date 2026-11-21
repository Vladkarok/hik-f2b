//! The decision logic: read new failures, count them, ban, notify.
//!
//! Two clocks are involved. Each NVR's log and read cursor are in that
//! device's local wall-clock time, which DST changes and which an RTC reset
//! can put decades off. Everything that is counted or compared across NVRs
//! (failure times, `findtime`, bans, the rate limit) is in host time; each
//! poll converts an NVR's entries with that NVR's current offset. The host
//! time is passed in (`cycle_at`), so tests can drive both clocks.
//!
//! Along the way the engine tells `health::Alerts` whether each NVR could be
//! read, whether the firewall could be used and whether bans are held back;
//! that module decides when this is worth an alert.

use crate::action::{
    render, BanError, BanInfo, BanTime, Firewall, HealthError, Notifier, NotifyError,
};
use crate::config::{Config, DEFAULT_MESSAGE};
use crate::country::{self, Code};
use crate::health::{Alerts, Check, CheckLine, Kind, Notice, Status};
use crate::mikrotik::Mikrotik;
use crate::nvr::{Event, Nvr, NvrError, Search};
use crate::state::{
    NvrState, Pending, State, MAX_BANNED, MAX_FAIL_TIMES, MAX_PENDING, MAX_SEEN, MAX_TRACKED,
};
use crate::telegram::Telegram;
use crate::util;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_QUEUED_NOTIFICATIONS: usize = 100;
const NOTIFY_ATTEMPTS: u32 = 5;
/// The longest wait for the messenger that is kept: one further away can
/// only come from the host clock having gone back.
const MAX_NOTIFY_WAIT: u64 = 3600;
/// Polls in a row that may fail for a reason other than authentication
/// before the read cursor is moved past whatever blocks it.
const MAX_FAILED_POLLS: u32 = 10;
/// Entries more than this far in the (host) future are not counted.
const MAX_FUTURE: i64 = 300;
/// A change of the device-minus-host offset larger than this between two
/// reads, in either direction, is a clock jump, not drift or a slow
/// request. Well below a DST change, well above what slow polls of several
/// NVRs add up to. A smaller change is taken as it is: entries logged before
/// it and read after it are converted with the new offset, so their host
/// times can be off by up to this much.
pub const CLOCK_JUMP: i64 = 900;
/// With `bantime = permanent` the router keeps the ban for ever, but what
/// hik-f2b remembers about an address still needs an end: how long a ban
/// that cannot be applied keeps waiting, and how long a reported address is
/// not reported again.
const PERMANENT_MEMORY: u64 = 86400;
/// Time between two health checks of the firewall.
pub const HEALTH_CHECK_INTERVAL: u64 = 300;
/// Searches of one NVR's log per poll, when the NVR lists newest first and
/// the window holds more than one search returns (see `read_window`). With
/// the caps in `nvr.rs` one poll reads at most this many times 50 pages or
/// 5000 entries.
const MAX_SEARCHES: usize = 4;

/// `--check` searches the log of the last day before the device time...
const CHECK_WINDOW: i64 = 86400;
/// ...and reads at most this many pages of it, so it stays quick on a busy
/// NVR. Two pages tell the page size and, mostly, the order.
const CHECK_PAGES: usize = 2;

/// The device clock against the host clock, for `--check`: what the engine
/// subtracts from device times.
fn describe_offset(offset: i64) -> String {
    let abs = offset.unsigned_abs();
    let hms = format!("{}:{:02}:{:02}", abs / 3600, abs / 60 % 60, abs % 60);
    match offset {
        0 => "same as the host clock".to_string(),
        o if o > 0 => format!("{} ahead of the host clock", hms),
        _ => format!("{} behind the host clock", hms),
    }
}

/// What a `--check` search showed about the NVR's log: the order of the
/// entries (the engine reads both, see `read_window`) and the page size.
fn describe_log(search: &Search) -> String {
    let times: Vec<i64> = search.events.iter().filter_map(|ev| ev.ts).collect();
    let up = times.windows(2).any(|w| w[0] < w[1]);
    let down = times.windows(2).any(|w| w[0] > w[1]);
    let order = match (up, down) {
        (true, false) => "oldest first",
        (false, true) => "newest first",
        (false, false) => "order not known",
        (true, true) => "neither oldest nor newest first",
    };
    let page = match search.page_size {
        Some(n) => format!("{} entries per page", n),
        None => "page size not known".to_string(),
    };
    let mut out = format!("{}, {}", order, page);
    if !(up || down) || search.page_size.is_none() {
        out.push_str(&format!(
            " ({} entries read from the last 24 h)",
            search.events.len()
        ));
    }
    out
}

/// How long the engine remembers a ban (see `PERMANENT_MEMORY`).
fn memory(bantime: BanTime) -> u64 {
    match bantime {
        BanTime::Seconds(s) => s,
        BanTime::Permanent => PERMANENT_MEMORY,
    }
}

pub struct Engine {
    pub cfg: Config,
    pub state: State,
    pub nvrs: Vec<Nvr>,
    pub firewall: Option<Box<dyn Firewall>>,
    pub notifier: Option<Box<dyn Notifier>>,
    template: String,
    notifications: Vec<(String, u32)>,
    alerts: Alerts,
    /// Host time of the next firewall health check.
    next_check: u64,
    /// The reason the last country lookup failed, if it did: a failure is
    /// logged when its reason changes, a recovery once.
    country_failure: Option<String>,
    /// Host time a banned address was last seen reaching an NVR well after
    /// its ban (see `Check::Bypassed`); `None` once that problem is over.
    last_bypass: Option<u64>,
    /// Set (by a signal handler) when the service is to stop. A cycle
    /// looks at it between its steps (see `cycle_at`).
    stop: Arc<AtomicBool>,
    /// Notifications not queued in this cycle because the queue was full.
    dropped_notifications: usize,
    /// Host time before which the messenger asked not to be sent anything.
    notify_after: u64,
}

/// Addresses that can never be a remote attacker, whatever the log says.
fn never_ban(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_link_local()
        || ip.octets()[0] == 0
        || ip.octets()[0] >= 240
}

/// Never banned: in `ignoreip`, or in a range `never_ban` names.
fn exempt(cfg: &Config, ip: Ipv4Addr) -> bool {
    never_ban(ip) || cfg.ignored(ip)
}

fn host_i64(host_now: u64) -> i64 {
    i64::try_from(host_now).unwrap_or(i64::MAX)
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
/// `seen` set; the rest of the engine never sees device time.
///
/// The first poll of an NVR reads from its current time. It records what
/// the `lookback` overlap before that holds as already seen, without
/// counting it, so failed logins from before the start are never counted.
/// Until that read succeeds the NVR stays unknown, and the next poll tries
/// again.
fn poll_nvr(
    nvr: &mut Nvr,
    cfg: &Config,
    state: &mut State,
    host_now: i64,
) -> Result<Polled, NvrError> {
    // An NVR that cannot be reached at all does not count towards skipping
    // a log window (`failed_polls`): only a log that cannot be read does.
    let now = nvr.now()?;
    let offset = now.saturating_sub(host_now);
    let first = !state.nvr.contains_key(&nvr.name);
    let st = state
        .nvr
        .entry(nvr.name.clone())
        .or_insert_with(|| NvrState {
            since: now,
            offset: Some(offset),
            ..Default::default()
        });
    let result = read_log(nvr, cfg, st, now, offset, first);
    if first && result.is_err() {
        state.nvr.remove(&nvr.name);
    }
    result
}

/// `poll_nvr` once the NVR's state exists (`first`: it was just made).
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
    st: &mut NvrState,
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

/// How many failure times are kept per address, and for how many addresses
/// at most: the newest `4 * maxretry` (at least 16) times, for as many
/// addresses as `MAX_FAIL_TIMES` allows, at most `MAX_TRACKED`.
pub fn fail_limits(maxretry: usize) -> (usize, usize) {
    let per_address = maxretry.saturating_mul(4).max(16);
    let addresses = (MAX_FAIL_TIMES / per_address).clamp(1, MAX_TRACKED);
    (per_address, addresses)
}

/// Forgets the addresses whose last failure is the oldest until at most
/// `keep` are tracked.
fn forget_oldest(state: &mut State, keep: usize) {
    if state.fails.len() <= keep {
        return;
    }
    let mut by_age: Vec<(i64, Ipv4Addr)> = state
        .fails
        .iter()
        .map(|(ip, times)| (times.iter().copied().max().unwrap_or(0), *ip))
        .collect();
    by_age.sort_unstable();
    let extra = state.fails.len() - keep;
    for (_, ip) in by_age.into_iter().take(extra) {
        state.fails.remove(&ip);
    }
}

/// Remembers that `ip` is handled until `until` (see `State::banned`). With
/// `MAX_BANNED` addresses remembered, the one whose end is nearest is
/// forgotten first: it would be the next to expire anyway.
fn remember_ban(state: &mut State, ip: Ipv4Addr, until: u64) {
    if !state.banned.contains_key(&ip) && state.banned.len() >= MAX_BANNED {
        let first = state
            .banned
            .iter()
            .min_by_key(|(ip, until)| (**until, **ip))
            .map(|(ip, _)| *ip);
        if let Some(first) = first {
            state.banned.remove(&first);
        }
    }
    state.banned.insert(ip, until);
}

/// Counts one failure at host time `ts`. Returns the ban to apply when the
/// limit is reached.
fn register(
    ev: &Event,
    ts: i64,
    host_now: i64,
    cfg: &Config,
    state: &mut State,
    report_once: bool,
) -> Option<(Ipv4Addr, Pending)> {
    let user = util::sanitize(&ev.user, 32);
    let ip = match ev.ip? {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(ip) => {
            crate::info!(
                "{}: failed login from {} (user={:?}): IPv6 is not handled",
                ev.nvr,
                ip,
                user
            );
            return None;
        }
    };
    if exempt(cfg, ip) {
        crate::info!(
            "{}: failed login from {} (user={:?}): never banned (ignoreip or reserved), not counted",
            ev.nvr,
            ip,
            user
        );
        return None;
    }
    if state.pending.contains_key(&ip) {
        return None;
    }
    // Without a firewall (or in a dry run) nothing stops the address, so it
    // would be reported again with every burst; once per bantime (24 hours
    // for a permanent one) is enough.
    if report_once
        && state
            .banned
            .get(&ip)
            .is_some_and(|until| host_i64(*until) > host_now)
    {
        crate::info!(
            "{}: failed login from {} (user={:?}): already reported",
            ev.nvr,
            ip,
            user
        );
        return None;
    }
    let (cap, addresses) = fail_limits(cfg.maxretry);
    if !state.fails.contains_key(&ip) && state.fails.len() >= addresses {
        // Forget the address whose last failure is the oldest.
        forget_oldest(state, addresses - 1);
    }
    let times = state.fails.entry(ip).or_default();
    times.push(ts);
    times.sort_unstable();
    let horizon = host_now.saturating_sub(cfg.findtime);
    times.retain(|t| *t >= horizon);
    if times.len() > cap {
        let extra = times.len() - cap;
        times.drain(..extra);
    }
    let count = times.len();
    crate::info!(
        "{}: failed login from {} (user={:?}) at {} [{}/{}]",
        ev.nvr,
        ip,
        user,
        util::fmt_ts(ts),
        count,
        cfg.maxretry
    );
    if count >= cfg.maxretry {
        Some((
            ip,
            Pending {
                ts,
                count,
                nvr: ev.nvr.clone(),
                user,
            },
        ))
    } else {
        None
    }
}

impl Engine {
    /// An engine with the router and Telegram clients the configuration
    /// asks for.
    pub fn new(cfg: Config, state: State) -> Result<Engine, String> {
        let firewall: Option<Box<dyn Firewall>> = match &cfg.mikrotik {
            Some(m) => Some(Box::new(Mikrotik::new(m)?)),
            None => None,
        };
        let notifier: Option<Box<dyn Notifier>> = match &cfg.telegram {
            Some(t) => Some(Box::new(Telegram::new(t)?)),
            None => None,
        };
        Engine::with_parts(cfg, state, firewall, notifier)
    }

    /// An engine with the given firewall and notifier (either may be absent).
    pub fn with_parts(
        cfg: Config,
        state: State,
        firewall: Option<Box<dyn Firewall>>,
        notifier: Option<Box<dyn Notifier>>,
    ) -> Result<Engine, String> {
        let nvrs = cfg
            .nvrs
            .iter()
            .map(Nvr::new)
            .collect::<Result<Vec<_>, _>>()?;
        let template = cfg
            .telegram
            .as_ref()
            .map(|t| t.message.clone())
            .unwrap_or_else(|| DEFAULT_MESSAGE.replace("\\n", "\n"));
        let mut engine = Engine {
            alerts: Alerts::new(cfg.alert_after),
            cfg,
            state,
            nvrs,
            firewall,
            notifier,
            template,
            notifications: Vec::new(),
            next_check: 0,
            country_failure: None,
            last_bypass: None,
            stop: Arc::new(AtomicBool::new(false)),
            dropped_notifications: 0,
            notify_after: 0,
        };
        // The state may come from a run with another `ignoreip`, or with a
        // `maxretry` that kept more failure times.
        engine.drop_exempt();
        let (cap, addresses) = fail_limits(engine.cfg.maxretry);
        for times in engine.state.fails.values_mut() {
            if times.len() > cap {
                let extra = times.len() - cap;
                times.drain(..extra);
            }
        }
        forget_oldest(&mut engine.state, addresses);
        Ok(engine)
    }

    /// Forgets the waiting ban and the counted failed logins of every
    /// address that is never banned. `register` keeps such addresses out,
    /// but `ignoreip` may have changed since they were counted (a restart
    /// with a new config), and a waiting ban must not be applied then.
    fn drop_exempt(&mut self) {
        let cfg = &self.cfg;
        let mut addresses: Vec<Ipv4Addr> = self
            .state
            .pending
            .keys()
            .chain(self.state.fails.keys())
            .copied()
            .filter(|ip| exempt(cfg, *ip))
            .collect();
        addresses.sort_unstable();
        addresses.dedup();
        for ip in addresses {
            let waiting = self.state.pending.remove(&ip).is_some();
            let counted = self.state.fails.remove(&ip).map_or(0, |times| times.len());
            let what = match (waiting, counted) {
                (true, 0) => "waiting ban dropped".to_string(),
                (true, n) => format!(
                    "waiting ban dropped, {} counted failed login(s) forgotten",
                    n
                ),
                (false, n) => format!("{} counted failed login(s) forgotten", n),
            };
            crate::info!(
                "{}: {}: the address is in ignoreip or a reserved range and is never banned",
                ip,
                what
            );
        }
    }

    /// The flag that stops the service: set it (from a signal handler) and
    /// the current cycle ends after its current step, see `cycle_at`.
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    fn stopping(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// The service: a cycle every `poll_interval` (or only one, with
    /// `once`) until the stop flag is set. The state is saved after every
    /// cycle in which it changed, also after a cycle that a stop cut short,
    /// so what that cycle learned is not lost.
    pub fn run(&mut self, state_file: &Path, once: bool) {
        // A hash of what was saved: the state is written out (line by line)
        // only when it changed, and never held as a second copy in memory.
        let mut saved = self.state.digest();
        while !self.stopping() {
            self.cycle();
            let current = self.state.digest();
            if current != saved {
                match self.state.save(state_file) {
                    Ok(()) => saved = current,
                    Err(e) => crate::error!(
                        "cannot save state to {}: {}",
                        state_file.display(),
                        e.kind()
                    ),
                }
            }
            if once {
                break;
            }
            let deadline = Instant::now() + Duration::from_secs(self.cfg.poll_interval);
            while !self.stopping() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(250));
            }
        }
    }

    /// Runs the firewall health check once at startup and logs the result;
    /// the first periodic check follows `HEALTH_CHECK_INTERVAL` later.
    /// Returns whether the firewall answered (so that more can be asked of
    /// it without waiting for a second timeout).
    pub fn startup_check(&mut self, host_now: u64) -> bool {
        match self.check_firewall(host_now) {
            None => false,
            Some(Ok(found)) => {
                crate::info!("firewall check ok: {}", found);
                true
            }
            Some(Err(e)) => {
                crate::error!(
                    "firewall check failed: {} (bans will keep being retried)",
                    e
                );
                matches!(e, HealthError::NotEnforced(_))
            }
        }
    }

    /// Logs which country database is configured, or why it cannot be
    /// read. Either way the service runs; without the file bans simply
    /// carry no country.
    pub fn startup_country(&mut self) {
        let Some(path) = self.cfg.country_db.clone() else {
            return;
        };
        match country::info(&path) {
            Ok(info) => crate::info!("country database: {}", info.describe()),
            Err(e) => {
                crate::warn!(
                    "country database cannot be read, bans go on without a country: {}",
                    e
                );
                self.country_failure = Some(e);
            }
        }
    }

    /// The country of `ip`, if `country_db` is set and knows it. A failed
    /// lookup never holds up a ban: it is logged when the reason changes
    /// (not on every retry of the same ban), and once when lookups work
    /// again. It is not a health alert.
    fn country(&mut self, ip: Ipv4Addr) -> Option<Code> {
        let path = self.cfg.country_db.as_ref()?;
        match country::lookup(path, ip) {
            Ok(code) => {
                if self.country_failure.take().is_some() {
                    crate::info!("country lookups work again");
                }
                code
            }
            Err(e) => {
                if self.country_failure.as_deref() != Some(e.as_str()) {
                    crate::warn!("country lookup failed, bans go on without a country: {}", e);
                    self.country_failure = Some(e);
                }
                None
            }
        }
    }

    /// One health check of the firewall; the outcome goes to the alerts.
    fn check_firewall(&mut self, host_now: u64) -> Option<Result<String, HealthError>> {
        let result = self.firewall.as_ref()?.check();
        self.next_check = host_now.saturating_add(HEALTH_CHECK_INTERVAL);
        match &result {
            Ok(_) => {
                self.alerts.pass(&Check::Firewall, host_now);
                self.alerts.pass(&Check::Rule, host_now);
            }
            Err(HealthError::Unusable(e)) => self.alerts.fail(Check::Firewall, e, host_now),
            Err(HealthError::NotEnforced(e)) => {
                self.alerts.pass(&Check::Firewall, host_now);
                self.alerts.fail(Check::Rule, e, host_now);
            }
        }
        Some(result)
    }

    /// The periodic firewall check, at most once per cycle. Skipped when a
    /// ban attempt in this cycle already found the firewall unusable: that
    /// is known, a second timeout would only delay the next poll, and a read
    /// that works must not end a problem that writes still show.
    fn periodic_check(&mut self, host_now: u64, unreachable: bool) {
        // A next check further away than the interval can only come from
        // the host clock having gone back.
        let due = host_now >= self.next_check || self.next_check - host_now > HEALTH_CHECK_INTERVAL;
        if !due || unreachable {
            return;
        }
        match self.check_firewall(host_now) {
            Some(Err(e)) => crate::warn!("firewall check failed: {}", e),
            Some(Ok(found)) => crate::debug!("firewall check ok: {}", found),
            None => {}
        }
    }

    /// Logs the health notices that are due and queues them for the chat.
    fn report_health(&mut self, host_now: u64) {
        let to_chat =
            self.notifier.is_some() && self.cfg.telegram.as_ref().is_none_or(|t| t.health_alerts);
        for notice in self.alerts.due(host_now) {
            log_notice(&notice);
            if to_chat {
                self.queue_notification(notice.text());
            }
        }
    }

    /// Queues a message for the chat; counts it as dropped when
    /// `MAX_QUEUED_NOTIFICATIONS` already wait.
    fn queue_notification(&mut self, text: String) {
        if self.notifications.len() < MAX_QUEUED_NOTIFICATIONS {
            self.notifications.push((text, 0));
        } else {
            self.dropped_notifications += 1;
        }
    }

    /// Problems that have been alerted and still persist, by key (for
    /// tests and diagnostics).
    pub fn alerted_problems(&self) -> Vec<String> {
        self.alerts.alerted()
    }

    /// `--check` at the current host time.
    pub fn check_all(&mut self) -> Vec<CheckLine> {
        self.check_all_at(util::unix_now())
    }

    /// `--check`: every health check once. Only reads: the state, the
    /// alerts and the firewall are left as they are, and nothing is sent.
    /// `host_now` is the host's Unix time.
    pub fn check_all_at(&mut self, host_now: u64) -> Vec<CheckLine> {
        let mut out = Vec::new();
        let meta_id = self.cfg.meta_id.clone();
        for nvr in self.nvrs.iter_mut() {
            // The device time proves that the NVR answers and accepts the
            // login; a search, that the user may search the log. The search
            // also shows what the engine relies on (see `describe_log`).
            let result = nvr.now().and_then(|now| {
                nvr.sample(
                    now.saturating_sub(CHECK_WINDOW),
                    now.saturating_add(60),
                    &meta_id,
                    CHECK_PAGES,
                )
                .map(|search| (now, search))
            });
            let (status, detail, log) = match result {
                Ok((now, search)) => (
                    Status::Ok,
                    format!(
                        "login accepted, device time {} ({}), log search works",
                        util::fmt_ts(now),
                        describe_offset(now.saturating_sub(host_i64(host_now)))
                    ),
                    Some(describe_log(&search)),
                ),
                Err(NvrError::Auth(e)) => (Status::Failed, format!("login rejected ({})", e), None),
                Err(NvrError::Other(e)) => (Status::Failed, e, None),
            };
            out.push(CheckLine {
                item: format!("nvr {}", nvr.name),
                status,
                detail,
            });
            if let Some(detail) = log {
                out.push(CheckLine {
                    item: format!("nvr {} log", nvr.name),
                    status: Status::Ok,
                    detail,
                });
            }
        }
        let (status, detail) = match &self.firewall {
            None => (Status::Off, "not configured (notify-only mode)".to_string()),
            Some(fw) => match fw.check() {
                Ok(found) => (Status::Ok, found),
                Err(e) => (Status::Failed, e.to_string()),
            },
        };
        out.push(CheckLine {
            item: "firewall".to_string(),
            status,
            detail,
        });
        let (status, detail) = match &self.cfg.telegram {
            None => (Status::Off, "not configured".to_string()),
            Some(t) => (
                Status::Ok,
                format!(
                    "configured, health alerts {}; nothing sent (see --test-notify)",
                    if t.health_alerts { "on" } else { "off" }
                ),
            ),
        };
        out.push(CheckLine {
            item: "telegram".to_string(),
            status,
            detail,
        });
        // A lookup proves that the search tree can be walked, not only that
        // the metadata can be read.
        let (status, detail) = match &self.cfg.country_db {
            None => (Status::Off, "not configured".to_string()),
            Some(path) => match country::info(path)
                .and_then(|info| country::lookup(path, Ipv4Addr::new(192, 0, 2, 1)).map(|_| info))
            {
                Ok(info) => (Status::Ok, info.describe()),
                Err(e) => (Status::Failed, e),
            },
        };
        out.push(CheckLine {
            item: "country database".to_string(),
            status,
            detail,
        });
        out
    }

    /// One full pass at the current host time.
    pub fn cycle(&mut self) {
        self.cycle_at(util::unix_now());
    }

    /// One full pass: poll every NVR, apply bans, send notifications.
    /// `host_now` is the host's Unix time.
    ///
    /// The stop flag is looked at before each step that may wait for a
    /// device: each NVR's poll, each ban, the firewall check and each
    /// notification. Once it is set the cycle skips what is left of these;
    /// what earlier steps learned (read positions, counted failed logins,
    /// waiting bans) is in the state, which the caller saves.
    pub fn cycle_at(&mut self, host_now: u64) {
        let now = host_i64(host_now);
        let report_once = self.firewall.is_none() || self.cfg.dry_run;
        // Whether every NVR was read in this cycle.
        let mut all_read = true;
        for i in 0..self.nvrs.len() {
            if self.stopping() {
                all_read = false;
                break;
            }
            let retry_after = self.nvrs[i].retry_after;
            if retry_after > host_now {
                // A wait longer than auth_backoff can only come from the
                // host clock jumping back; do not wait for years.
                if retry_after - host_now <= self.cfg.auth_backoff {
                    all_read = false;
                    continue;
                }
                self.nvrs[i].retry_after = 0;
            }
            let check = Check::Nvr(self.nvrs[i].name.clone());
            match poll_nvr(&mut self.nvrs[i], &self.cfg, &mut self.state, now) {
                Err(NvrError::Auth(e)) => {
                    self.nvrs[i].retry_after = host_now.saturating_add(self.cfg.auth_backoff);
                    crate::error!(
                        "{}: login to the NVR was rejected ({}). Check the user, the password and the \
                         'Remote: Log Search' permission. Next try in {} s.",
                        self.nvrs[i].name,
                        e,
                        self.cfg.auth_backoff
                    );
                    // The NVR is not polled while backing off, so the
                    // problem stays open until the next attempt.
                    let reason = format!("login rejected ({})", e);
                    self.alerts.fail(check, &reason, host_now);
                    all_read = false;
                }
                Err(NvrError::Other(e)) => {
                    crate::warn!("{}: poll failed: {}", self.nvrs[i].name, e);
                    self.alerts.fail(check, &e, host_now);
                    all_read = false;
                }
                Ok(polled) => {
                    self.alerts.pass(&check, host_now);
                    self.count(polled, now, report_once);
                }
            }
        }
        let unreachable = self.stopping() || self.flush_pending(host_now);
        self.bypass_over(host_now, all_read);
        if !self.stopping() {
            self.periodic_check(host_now, unreachable);
        }
        self.report_health(host_now);
        self.flush_notifications(host_now);
        self.cleanup(host_now);
        if self.stopping() {
            crate::info!(
                "stop requested: the rest of this poll is skipped; waiting bans and \
                 notifications wait for the next start"
            );
        }
    }

    /// Ends the `Check::Bypassed` problem once no banned address has
    /// reached an NVR for `alert_after`, counted only while every NVR is
    /// read (an NVR that cannot be read shows nothing either way). An
    /// attacker that pauses for less than that does not end it; so it is
    /// alerted when banned addresses keep reaching the NVRs for
    /// `alert_after` without such a pause.
    fn bypass_over(&mut self, now: u64, all_read: bool) {
        let Some(last) = self.last_bypass else {
            return;
        };
        // A last time in the future can only come from the host clock
        // having gone back: count from now.
        let last = last.min(now);
        self.last_bypass = Some(last);
        if all_read && now - last >= self.cfg.alert_after {
            self.alerts.pass(&Check::Bypassed, now);
            self.last_bypass = None;
        }
    }

    /// Counts one NVR's new failures at host time and queues the bans
    /// they call for.
    fn count(&mut self, polled: Polled, now: i64, report_once: bool) {
        for ev in &polled.fresh {
            let Some(ts) = ev.ts else { continue };
            let host_ts = ts.saturating_sub(polled.offset);
            if host_ts < now.saturating_sub(self.cfg.findtime)
                || host_ts > now.saturating_add(MAX_FUTURE)
            {
                crate::debug!(
                    "{}: entry at {} (device time) is outside the counting window, not counted",
                    ev.nvr,
                    util::fmt_ts(ts)
                );
                continue;
            }
            if let Some((ip, pending)) =
                register(ev, host_ts, now, &self.cfg, &mut self.state, report_once)
            {
                self.queue_ban(ip, pending);
            }
        }
    }

    fn queue_ban(&mut self, ip: Ipv4Addr, pending: Pending) {
        if self.state.pending.len() >= MAX_PENDING {
            let oldest = self
                .state
                .pending
                .iter()
                .min_by_key(|(ip, p)| (p.ts, **ip))
                .map(|(ip, _)| *ip);
            if let Some(oldest) = oldest {
                self.state.pending.remove(&oldest);
                crate::warn!(
                    "{} bans are already waiting; the oldest ({}) is dropped",
                    MAX_PENDING,
                    oldest
                );
            }
        }
        self.state.pending.insert(ip, pending);
    }

    /// Applies waiting bans. Returns true when the firewall turned out to be
    /// unusable (unreachable, refusing our login or answering with an
    /// error), which ends the attempts for this cycle.
    fn flush_pending(&mut self, now: u64) -> bool {
        // A ban time in the future can only come from the host clock having
        // been ahead; keep it as "now" so it still counts for an hour.
        for t in self.state.recent_bans.iter_mut() {
            *t = (*t).min(now);
        }
        self.state
            .recent_bans
            .retain(|t| now.saturating_sub(*t) < 3600);
        self.drop_exempt();

        let bantime = self.cfg.bantime;
        let keep = memory(bantime);
        let expired: Vec<Ipv4Addr> = self
            .state
            .pending
            .iter()
            .filter(|(_, p)| host_i64(now).saturating_sub(p.ts) > host_i64(keep))
            .map(|(ip, _)| *ip)
            .collect();
        let limit = match bantime {
            BanTime::Seconds(s) => format!("bantime ({} s)", s),
            BanTime::Permanent => format!("{} s", keep),
        };
        for ip in expired {
            crate::warn!(
                "{}: the ban could not be applied within {} and is dropped",
                ip,
                limit
            );
            self.state.pending.remove(&ip);
        }

        // Oldest first: the address that reached the threshold first has
        // been waiting longest.
        let mut order: Vec<(i64, Ipv4Addr)> = self
            .state
            .pending
            .iter()
            .map(|(ip, p)| (p.ts, *ip))
            .collect();
        order.sort_unstable();
        let mut limited = false;
        let mut unreachable = false;
        let mut stopped = false;
        for (_, ip) in order {
            if self.stopping() {
                stopped = true;
                break;
            }
            let Some(p) = self.state.pending.get(&ip).cloned() else {
                continue;
            };
            // A safety valve: whatever goes wrong upstream, never flood the
            // router's address-list (or the chat).
            if self.state.recent_bans.len() >= self.cfg.max_bans_per_hour {
                crate::warn!(
                    "ban rate limit reached ({} per hour), {} address(es) are waiting",
                    self.cfg.max_bans_per_hour,
                    self.state.pending.len()
                );
                limited = true;
                break;
            }
            // Display only, and looked up after every decision is made.
            let code = self.country(ip);
            // At the end: after the fixed-format time, where the user name
            // (attacker-chosen, up to 32 characters) cannot reach. The whole
            // comment stays within 110 characters.
            let comment = util::sanitize(
                &format!(
                    "hik-f2b {} user={} {}{}",
                    p.nvr,
                    p.user,
                    util::fmt_ts(p.ts),
                    code.map(|c| format!(" country={}", c)).unwrap_or_default()
                ),
                120,
            );
            // `198.51.100.7 [MD]` in the log
            let shown = match code {
                Some(c) => format!("{} [{}]", ip, c),
                None => ip.to_string(),
            };
            let duration = bantime.phrase();
            // (what happened, uses rate-limit allowance, worth a notification)
            let (action, counted, notify) = match &self.firewall {
                None => {
                    crate::warn!(
                        "DETECTED {} (no firewall configured, not banned) ({})",
                        shown,
                        comment
                    );
                    ("detected, no firewall configured".to_string(), true, true)
                }
                Some(_) if self.cfg.dry_run => {
                    crate::warn!("DRY RUN: would ban {} {} ({})", shown, duration, comment);
                    (
                        format!("would be banned {} (dry run)", duration),
                        true,
                        true,
                    )
                }
                Some(fw) => match fw.ban(ip, bantime, &comment) {
                    Err(BanError::Refused(e)) => {
                        crate::error!("cannot ban {} on {}, will retry: {}", ip, fw.describe(), e);
                        // A successful read does not clear this: only a
                        // ban the firewall accepts does.
                        let reason = format!("{}: {}", ip, e);
                        self.alerts.fail(Check::BanRefused, &reason, now);
                        continue;
                    }
                    Err(e) => {
                        // The firewall cannot be reached, refuses our login
                        // or answers with an error: every further attempt
                        // would fail the same way (an unreachable one only
                        // after the same timeout, holding up the next poll).
                        // One problem, one alert: the periodic check would
                        // report the same login or router trouble.
                        crate::error!(
                            "cannot ban {} on {}, will retry next cycle: {}",
                            ip,
                            fw.describe(),
                            e
                        );
                        self.alerts.fail(Check::Firewall, &e.to_string(), now);
                        unreachable = true;
                        break;
                    }
                    Ok(true) => {
                        self.alerts.pass(&Check::Firewall, now);
                        self.alerts.pass(&Check::BanRefused, now);
                        crate::warn!("BAN {} {} ({})", shown, duration, comment);
                        (format!("banned {}", duration), true, true)
                    }
                    Ok(false) => {
                        self.alerts.pass(&Check::Firewall, now);
                        self.alerts.pass(&Check::BanRefused, now);
                        // The router is the source of truth for bans. A
                        // listed address should not reach the NVR, unless
                        // these failures were logged just before our ban.
                        // The time of the ban is kept (see below), so an
                        // attacker that keeps going cannot hide this.
                        let banned_at = self
                            .state
                            .banned
                            .get(&ip)
                            .map(|until| until.saturating_sub(keep));
                        let grace = self.cfg.poll_interval.saturating_mul(2).saturating_add(60);
                        if now.saturating_sub(banned_at.unwrap_or(0)) > grace {
                            crate::warn!(
                                "{} is already in {} but still reached the NVR; \
                                 if this repeats, check the firewall drop rule for that list",
                                ip,
                                fw.describe()
                            );
                            let since = match banned_at {
                                Some(at) => format!(
                                    "has been in {} for {}",
                                    fw.describe(),
                                    crate::health::fmt_duration(now.saturating_sub(at))
                                ),
                                None => format!("is in {}", fw.describe()),
                            };
                            let reason = format!("{} {} and still reached {}", ip, since, p.nvr);
                            self.alerts.fail(Check::Bypassed, &reason, now);
                            self.last_bypass = Some(now);
                        } else {
                            crate::info!("{} is already in {}", ip, fw.describe());
                        }
                        (String::new(), false, false)
                    }
                },
            };
            // Already listed: keep the time of the ban this engine knows, if
            // any (an address listed by hand counts from now).
            if counted || !self.state.banned.contains_key(&ip) {
                remember_ban(&mut self.state, ip, now.saturating_add(keep));
            }
            self.state.fails.remove(&ip);
            self.state.pending.remove(&ip);
            if counted {
                self.state.recent_bans.push(now);
            }
            if notify && self.notifier.is_some() {
                // The flag only goes to the chat.
                let country = code
                    .map(|c| format!(" ({} {})", c.flag(), c))
                    .unwrap_or_default();
                let text = render(
                    &self.template,
                    &BanInfo {
                        ip,
                        country: &country,
                        action: &action,
                        bantime: &bantime.label(),
                        nvr: &p.nvr,
                        user: &p.user,
                        count: p.count,
                        findtime: self.cfg.findtime,
                    },
                );
                self.queue_notification(text);
            }
        }
        if limited {
            let reason = format!(
                "{} address(es) waiting, limit {} per hour",
                self.state.pending.len(),
                self.cfg.max_bans_per_hour
            );
            self.alerts.fail(Check::RateLimit, &reason, now);
        } else if !unreachable && !stopped {
            self.alerts.pass(&Check::RateLimit, now);
        }
        if self.state.pending.is_empty() {
            // Every refused ban expired or was dropped: nothing is left to
            // show whether the firewall would accept one now.
            self.alerts.withdraw(&Check::BanRefused, now);
        }
        unreachable
    }

    /// Notifications never hold up a ban: they are sent afterwards and
    /// retried on later cycles if the messenger is unreachable. The first
    /// failure ends the attempt for this cycle, so an unreachable service
    /// costs at most one timeout per cycle. When the messenger asks to wait
    /// (too many messages), nothing is sent until then, and that wait is not
    /// a failed attempt.
    fn flush_notifications(&mut self, now: u64) {
        if self.dropped_notifications > 0 {
            crate::warn!(
                "{} notification(s) dropped: {} already wait to be sent",
                self.dropped_notifications,
                MAX_QUEUED_NOTIFICATIONS
            );
            self.dropped_notifications = 0;
        }
        let Some(notifier) = &self.notifier else {
            self.notifications.clear();
            return;
        };
        if self.notify_after > now {
            if self.notify_after - now <= MAX_NOTIFY_WAIT {
                return;
            }
            self.notify_after = 0;
        }
        while let Some((text, attempts)) = self.notifications.first().cloned() {
            if self.stop.load(Ordering::Relaxed) {
                break;
            }
            match notifier.send(&text) {
                Ok(()) => {
                    crate::debug!("notification sent");
                    self.notifications.remove(0);
                }
                Err(NotifyError::RateLimited(wait)) => {
                    crate::info!(
                        "Telegram asks to wait {} s before the next message; {} notification(s) \
                         wait",
                        wait,
                        self.notifications.len()
                    );
                    self.notify_after = now.saturating_add(wait);
                    break;
                }
                Err(NotifyError::Failed(e)) => {
                    if attempts + 1 >= NOTIFY_ATTEMPTS {
                        crate::error!(
                            "notification dropped after {} attempts: {}",
                            NOTIFY_ATTEMPTS,
                            e
                        );
                        self.notifications.remove(0);
                    } else {
                        crate::warn!("notification failed, will retry: {}", e);
                        self.notifications[0].1 = attempts + 1;
                    }
                    break;
                }
            }
        }
    }

    fn cleanup(&mut self, host_now: u64) {
        let keep = memory(self.cfg.bantime);
        // An end further away than `keep` can only come from the host clock
        // having been ahead; such an entry would otherwise live for years.
        self.state
            .banned
            .retain(|_, until| *until > host_now && *until - host_now <= keep);
        let now = host_i64(host_now);
        let horizon = now.saturating_sub(self.cfg.findtime);
        let future = now.saturating_add(MAX_FUTURE);
        self.state.fails.retain(|_, times| {
            times.retain(|t| *t >= horizon && *t <= future);
            !times.is_empty()
        });
    }

    /// Notifications waiting to be sent (for tests and diagnostics).
    pub fn queued_notifications(&self) -> usize {
        self.notifications.len()
    }
}

/// One log line per health notice: ERROR for an alert or a reminder, INFO
/// for a recovery.
fn log_notice(notice: &Notice) {
    let text = notice.text();
    // The log does without the symbol that starts the chat message.
    let text = text.split_once(' ').map_or(text.as_str(), |(_, rest)| rest);
    let key = notice.check.key();
    match notice.kind {
        Kind::Alert => crate::error!("health alert [{}]: {}", key, text),
        Kind::Reminder => crate::error!("health reminder [{}]: {}", key, text),
        Kind::Recovered => crate::info!("health recovered [{}]: {}", key, text),
        Kind::Unknown => crate::info!("health unknown [{}]: {}", key, text),
    }
}
