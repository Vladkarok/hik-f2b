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

use crate::action::{render, BanError, BanInfo, BanTime, Firewall, HealthError, Notifier};
use crate::config::{Config, DEFAULT_MESSAGE};
use crate::health::{Alerts, Check, CheckLine, Kind, Notice, Status};
use crate::mikrotik::Mikrotik;
use crate::nvr::{Event, Nvr, NvrError};
use crate::state::{Pending, State, MAX_PENDING, MAX_SEEN, MAX_TRACKED};
use crate::telegram::Telegram;
use crate::util;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

const MAX_QUEUED_NOTIFICATIONS: usize = 100;
const NOTIFY_ATTEMPTS: u32 = 5;
/// Polls in a row that may fail for a reason other than authentication
/// before the read cursor is moved past whatever blocks it.
const MAX_FAILED_POLLS: u32 = 10;
/// Entries more than this far in the (host) future are not counted.
const MAX_FUTURE: i64 = 300;
/// A change of the device-minus-host offset larger than this between two
/// polls is a clock jump, not drift or a slow request. Well below a DST
/// change, well above what slow polls of several NVRs add up to.
const CLOCK_JUMP: i64 = 900;
/// With `bantime = permanent` the router keeps the ban for ever, but what
/// hik-f2b remembers about an address still needs an end: how long a ban
/// that cannot be applied keeps waiting, and how long a reported address is
/// not reported again.
const PERMANENT_MEMORY: u64 = 86400;
/// Time between two health checks of the firewall.
pub const HEALTH_CHECK_INTERVAL: u64 = 300;

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

fn host_i64(host_now: u64) -> i64 {
    i64::try_from(host_now).unwrap_or(i64::MAX)
}

/// New failed logins of one NVR and the offset (device minus host time)
/// that converts their times to host time.
struct Polled {
    fresh: Vec<Event>,
    offset: i64,
}

/// Reads one NVR's log. Owns the read cursor (`since`, device time) and the
/// `seen` set; the rest of the engine never sees device time.
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
    let lookback = cfg.lookback;
    let Some(st) = state.nvr.get_mut(&nvr.name) else {
        state.nvr.insert(
            nvr.name.clone(),
            crate::state::NvrState {
                since: now,
                offset: Some(offset),
                ..Default::default()
            },
        );
        nvr.failed_polls = 0;
        crate::info!(
            "{}: first run, watching log entries from {} (device time)",
            nvr.name,
            util::fmt_ts(now)
        );
        return Ok(Polled {
            fresh: Vec::new(),
            offset,
        });
    };

    // After a clock jump the device log holds entries whose times say
    // nothing about when they happened relative to new ones. Resync: read
    // from the new time, and record what the first window holds without
    // counting it, so old entries are never counted (again).
    let mut since = st.since;
    let mut baseline = false;
    if now < since.saturating_sub(lookback) {
        crate::warn!(
            "{}: device clock went back from {} to {}; reading on from the new time, \
             entries already in the log are not counted",
            nvr.name,
            util::fmt_ts(since),
            util::fmt_ts(now)
        );
        since = now;
        baseline = true;
    } else if let Some(previous) = st.offset {
        let jump = offset.saturating_sub(previous);
        if jump > CLOCK_JUMP {
            crate::warn!(
                "{}: device clock jumped forward by {} s (to {}); reading on from the new time, \
                 entries already in the log are not counted",
                nvr.name,
                jump,
                util::fmt_ts(now)
            );
            since = now;
            baseline = true;
        }
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

    let result = nvr.search(
        since.saturating_sub(lookback),
        now.saturating_add(86400),
        &cfg.meta_id,
        None,
    );
    let search = match result {
        Ok(search) => search,
        Err(NvrError::Other(e)) => {
            nvr.failed_polls = nvr.failed_polls.saturating_add(1);
            if nvr.failed_polls >= MAX_FAILED_POLLS {
                // Without this a single entry the NVR cannot deliver would
                // stop the daemon from ever reading on.
                crate::error!(
                    "{}: the log could not be read {} times in a row; SKIPPING the log window \
                     {} .. {} (device time), failed logins in it are not counted",
                    nvr.name,
                    nvr.failed_polls,
                    util::fmt_ts(since.saturating_sub(lookback)),
                    util::fmt_ts(now)
                );
                st.since = now;
                st.offset = Some(offset);
                nvr.failed_polls = 0;
            }
            return Err(NvrError::Other(e));
        }
        Err(e) => return Err(e),
    };
    nvr.failed_polls = 0;

    let mut counter: HashMap<String, u32> = HashMap::new();
    let mut by_key: HashMap<String, Event> = HashMap::new();
    let mut newest = since;
    for ev in search.events {
        if let Some(ts) = ev.ts {
            newest = newest.max(ts);
        }
        if !cfg.log_filter.is_match(&ev.meta) {
            continue;
        }
        if ev.ts.is_none() || ev.ip.is_none() {
            crate::debug!("{}: entry without time or address skipped", nvr.name);
            continue;
        }
        let n = counter.entry(ev.key.clone()).or_insert(0);
        *n = n.saturating_add(1);
        by_key.insert(ev.key.clone(), ev);
    }

    // The search window overlaps the previous one, so an entry is new only
    // if it occurs more often than it did in the previous poll.
    let mut fresh = Vec::new();
    if baseline {
        crate::info!(
            "{}: {} existing log entr{} recorded as already seen",
            nvr.name,
            counter.len(),
            if counter.len() == 1 { "y" } else { "ies" }
        );
    } else {
        for (key, count) in &counter {
            let before = st.seen.get(key).copied().unwrap_or(0);
            if let Some(ev) = by_key.get(key) {
                for _ in before..*count {
                    fresh.push(ev.clone());
                }
            }
        }
    }
    fresh.sort_by_key(|ev| ev.ts);

    let mut next = newest.min(now);
    if search.truncated && !baseline {
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
    // Never ahead of the device clock, or a backward jump would go unseen.
    st.since = next.min(now);
    st.offset = Some(offset);
    Ok(Polled { fresh, offset })
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
    if never_ban(ip) || cfg.ignored(ip) {
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
    if !state.fails.contains_key(&ip) && state.fails.len() >= MAX_TRACKED {
        // Forget the address whose last failure is the oldest.
        let oldest = state
            .fails
            .iter()
            .min_by_key(|(_, times)| times.iter().copied().max().unwrap_or(0))
            .map(|(ip, _)| *ip);
        if let Some(oldest) = oldest {
            state.fails.remove(&oldest);
        }
    }
    let times = state.fails.entry(ip).or_default();
    times.push(ts);
    times.sort_unstable();
    let horizon = host_now.saturating_sub(cfg.findtime);
    times.retain(|t| *t >= horizon);
    let cap = cfg.maxretry.saturating_mul(4).max(16);
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
        Ok(Engine {
            alerts: Alerts::new(cfg.alert_after),
            cfg,
            state,
            nvrs,
            firewall,
            notifier,
            template,
            notifications: Vec::new(),
            next_check: 0,
        })
    }

    /// Runs the firewall health check once at startup and logs the result;
    /// the first periodic check follows `HEALTH_CHECK_INTERVAL` later.
    pub fn startup_check(&mut self, host_now: u64) {
        match self.check_firewall(host_now) {
            None => {}
            Some(Ok(found)) => crate::info!("firewall check ok: {}", found),
            Some(Err(e)) => crate::error!(
                "firewall check failed: {} (bans will keep being retried)",
                e
            ),
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
    /// ban attempt in this cycle already found the firewall unreachable:
    /// that is known, and a second timeout would only delay the next poll.
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
            if to_chat && self.notifications.len() < MAX_QUEUED_NOTIFICATIONS {
                self.notifications.push((notice.text(), 0));
            }
        }
    }

    /// Problems that have been alerted and still persist, by key (for
    /// tests and diagnostics).
    pub fn alerted_problems(&self) -> Vec<String> {
        self.alerts.alerted()
    }

    /// `--check`: every health check once. Only reads: the state, the
    /// alerts and the firewall are left as they are, and nothing is sent.
    pub fn check_all(&mut self) -> Vec<CheckLine> {
        let mut out = Vec::new();
        let meta_id = self.cfg.meta_id.clone();
        for nvr in self.nvrs.iter_mut() {
            // The device time proves that the NVR answers and accepts the
            // login; a short search, that the user may search the log.
            let result = nvr.now().and_then(|now| {
                nvr.search(
                    now.saturating_sub(60),
                    now.saturating_add(60),
                    &meta_id,
                    None,
                )
                .map(|_| now)
            });
            let (status, detail) = match result {
                Ok(now) => (
                    Status::Ok,
                    format!(
                        "login accepted, device time {}, log search works",
                        util::fmt_ts(now)
                    ),
                ),
                Err(NvrError::Auth(e)) => (Status::Failed, format!("login rejected ({})", e)),
                Err(NvrError::Other(e)) => (Status::Failed, e),
            };
            out.push(CheckLine {
                item: format!("nvr {}", nvr.name),
                status,
                detail,
            });
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
        out
    }

    /// One full pass at the current host time.
    pub fn cycle(&mut self) {
        self.cycle_at(util::unix_now());
    }

    /// One full pass: poll every NVR, apply bans, send notifications.
    /// `host_now` is the host's Unix time.
    pub fn cycle_at(&mut self, host_now: u64) {
        let now = host_i64(host_now);
        let report_once = self.firewall.is_none() || self.cfg.dry_run;
        for i in 0..self.nvrs.len() {
            let retry_after = self.nvrs[i].retry_after;
            if retry_after > host_now {
                // A wait longer than auth_backoff can only come from the
                // host clock jumping back; do not wait for years.
                if retry_after - host_now <= self.cfg.auth_backoff {
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
                }
                Err(NvrError::Other(e)) => {
                    crate::warn!("{}: poll failed: {}", self.nvrs[i].name, e);
                    self.alerts.fail(check, &e, host_now);
                }
                Ok(polled) => {
                    self.alerts.pass(&check, host_now);
                    for ev in &polled.fresh {
                        let Some(ts) = ev.ts else { continue };
                        let host_ts = ts.saturating_sub(polled.offset);
                        if host_ts < now.saturating_sub(self.cfg.findtime)
                            || host_ts > now.saturating_add(MAX_FUTURE)
                        {
                            crate::debug!(
                                "{}: entry at {} (device time) is outside the counting window, \
                                 not counted",
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
            }
        }
        let unreachable = self.flush_pending(host_now);
        self.periodic_check(host_now, unreachable);
        self.report_health(host_now);
        self.flush_notifications();
        self.cleanup(host_now);
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
    /// unreachable.
    fn flush_pending(&mut self, host_now: u64) -> bool {
        let now = host_now;
        // A ban time in the future can only come from the host clock having
        // been ahead; keep it as "now" so it still counts for an hour.
        for t in self.state.recent_bans.iter_mut() {
            *t = (*t).min(now);
        }
        self.state
            .recent_bans
            .retain(|t| now.saturating_sub(*t) < 3600);

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
        for (_, ip) in order {
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
            let comment = util::sanitize(
                &format!("hik-f2b {} user={} {}", p.nvr, p.user, util::fmt_ts(p.ts)),
                120,
            );
            let duration = bantime.phrase();
            // (what happened, uses rate-limit allowance, worth a notification)
            let (action, counted, notify) = match &self.firewall {
                None => {
                    crate::warn!(
                        "DETECTED {} (no firewall configured, not banned) ({})",
                        ip,
                        comment
                    );
                    ("detected, no firewall configured".to_string(), true, true)
                }
                Some(_) if self.cfg.dry_run => {
                    crate::warn!("DRY RUN: would ban {} {} ({})", ip, duration, comment);
                    (
                        format!("would be banned {} (dry run)", duration),
                        true,
                        true,
                    )
                }
                Some(fw) => match fw.ban(ip, bantime, &comment) {
                    Err(BanError::Transport(e)) => {
                        // Every further attempt would wait for the same
                        // timeout and hold up the next poll.
                        crate::error!(
                            "cannot ban {} on {}, will retry next cycle: {}",
                            ip,
                            fw.describe(),
                            e
                        );
                        let reason = BanError::Transport(e).to_string();
                        self.alerts.fail(Check::Firewall, &reason, now);
                        unreachable = true;
                        break;
                    }
                    Err(BanError::Refused(e)) => {
                        crate::error!("cannot ban {} on {}, will retry: {}", ip, fw.describe(), e);
                        continue;
                    }
                    Ok(true) => {
                        self.alerts.pass(&Check::Firewall, now);
                        crate::warn!("BAN {} {} ({})", ip, duration, comment);
                        (format!("banned {}", duration), true, true)
                    }
                    Ok(false) => {
                        self.alerts.pass(&Check::Firewall, now);
                        // The router is the source of truth for bans. A
                        // listed address should not reach the NVR, unless
                        // these failures were logged just before our ban.
                        let banned_at = self
                            .state
                            .banned
                            .get(&ip)
                            .map(|until| until.saturating_sub(keep))
                            .unwrap_or(0);
                        let grace = self.cfg.poll_interval.saturating_mul(2).saturating_add(60);
                        if now.saturating_sub(banned_at) > grace {
                            crate::warn!(
                                "{} is already in {} but still reached the NVR; \
                                 if this repeats, check the firewall drop rule for that list",
                                ip,
                                fw.describe()
                            );
                        } else {
                            crate::info!("{} is already in {}", ip, fw.describe());
                        }
                        (String::new(), false, false)
                    }
                },
            };
            self.state.banned.insert(ip, now.saturating_add(keep));
            self.state.fails.remove(&ip);
            self.state.pending.remove(&ip);
            if counted {
                self.state.recent_bans.push(now);
            }
            if notify
                && self.notifier.is_some()
                && self.notifications.len() < MAX_QUEUED_NOTIFICATIONS
            {
                let text = render(
                    &self.template,
                    &BanInfo {
                        ip,
                        action: &action,
                        bantime: &bantime.label(),
                        nvr: &p.nvr,
                        user: &p.user,
                        count: p.count,
                        findtime: self.cfg.findtime,
                    },
                );
                self.notifications.push((text, 0));
            }
        }
        if limited {
            let reason = format!(
                "{} address(es) waiting, limit {} per hour",
                self.state.pending.len(),
                self.cfg.max_bans_per_hour
            );
            self.alerts.fail(Check::RateLimit, &reason, now);
        } else if !unreachable {
            self.alerts.pass(&Check::RateLimit, now);
        }
        unreachable
    }

    /// Notifications never hold up a ban: they are sent afterwards and
    /// retried on later cycles if the messenger is unreachable. The first
    /// failure ends the attempt for this cycle, so an unreachable service
    /// costs at most one timeout per cycle.
    fn flush_notifications(&mut self) {
        let Some(notifier) = &self.notifier else {
            self.notifications.clear();
            return;
        };
        while let Some((text, attempts)) = self.notifications.first().cloned() {
            match notifier.send(&text) {
                Ok(()) => {
                    crate::debug!("notification sent");
                    self.notifications.remove(0);
                }
                Err(e) => {
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
    }
}
