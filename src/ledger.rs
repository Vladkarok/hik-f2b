//! The ban ledger: the rules that decide whether and when an address is
//! banned. It counts failed logins per address, holds the bans that wait to
//! be applied, remembers the addresses that are banned (or reported) and the
//! times of the recent bans (the hourly rate limit), each within its bound.
//!
//! It has no I/O. Host time is an argument, never read from the clock; what
//! a device was asked and what it answered is told to it as an `Outcome`.
//! The engine asks it which bans are due (`due`, then `next_ban` for each),
//! does the device work and tells it how each attempt ended (`outcome`).
//! The ledger writes and reads its own lines of the state file.

use crate::action::BanTime;
use crate::config::{Config, Net};
use crate::state::{time, utime};
use crate::util::{self, host_i64};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::net::Ipv4Addr;

/// Upper bound on addresses with a running failure counter.
pub const MAX_TRACKED: usize = 10_000;
/// Upper bound on the failure times of all addresses together. With
/// `maxretry` above 5 the ledger keeps more times per address (see
/// `fail_limits`) and so tracks fewer addresses.
pub const MAX_FAIL_TIMES: usize = 200_000;
/// Upper bound on bans waiting to be applied.
pub const MAX_PENDING: usize = 1000;
/// Failure times kept per address in a state file that is read (the ledger
/// keeps fewer, see `fail_limits`).
const MAX_TIMES: usize = 4096;
/// Upper bound on banned (or reported) addresses remembered.
pub const MAX_BANNED: usize = 100_000;
/// Upper bound on the recent ban times read from a state file.
pub(crate) const MAX_RATE: usize = 10_000;
/// Longest user name kept for a failed login, in characters: when it is
/// counted (`engine.rs`) and when a waiting ban is read from a state file.
/// It goes into the router comment of the ban.
pub const MAX_USER: usize = 32;
/// Failed logins more than this far in the (host) future are not counted.
pub const MAX_FUTURE: i64 = 300;
/// With `bantime = permanent` the router keeps the ban for ever, but what
/// hik-f2b remembers about an address still needs an end: how long a ban
/// that cannot be applied keeps waiting, and how long a reported address is
/// not reported again.
const PERMANENT_MEMORY: u64 = 86400;

/// How long the ledger remembers a ban (see `PERMANENT_MEMORY`).
fn memory(bantime: BanTime) -> u64 {
    match bantime {
        BanTime::Seconds(s) => s,
        BanTime::Permanent => PERMANENT_MEMORY,
    }
}

/// How many failure times are kept per address, and for how many addresses
/// at most: the newest `4 * maxretry` (at least 16) times, for as many
/// addresses as `MAX_FAIL_TIMES` allows, at most `MAX_TRACKED`.
pub fn fail_limits(maxretry: usize) -> (usize, usize) {
    let per_address = maxretry.saturating_mul(4).max(16);
    let addresses = (MAX_FAIL_TIMES / per_address).clamp(1, MAX_TRACKED);
    (per_address, addresses)
}

/// Addresses that can never be a remote attacker, whatever the log says.
pub fn never_ban(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_link_local()
        || ip.octets()[0] == 0
        || ip.octets()[0] >= 240
}

/// The settings the ledger works with, taken from the config at the moment
/// of each call.
#[derive(Clone, Copy, Debug)]
pub struct Rules<'a> {
    pub maxretry: usize,
    pub findtime: i64,
    pub bantime: BanTime,
    pub max_bans_per_hour: usize,
    /// `ignoreip`.
    pub ignore: &'a [Net],
    /// The own addresses (`own.rs`), as last found. The ledger is told
    /// them; it never looks anything up.
    pub own: &'a BTreeSet<Ipv4Addr>,
}

/// Why an address is never banned.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Exempt {
    /// In `ignoreip`, or in a range `never_ban` names.
    Ignored,
    /// An own address of hik-f2b.
    Own,
}

impl<'a> Rules<'a> {
    pub fn of(cfg: &'a Config, own: &'a BTreeSet<Ipv4Addr>) -> Rules<'a> {
        Rules {
            maxretry: cfg.maxretry,
            findtime: cfg.findtime,
            bantime: cfg.bantime,
            max_bans_per_hour: cfg.max_bans_per_hour,
            ignore: &cfg.ignore,
            own,
        }
    }

    /// Why `ip` is never banned, if it is: a reserved range first (its
    /// line has always said "ignoreip or reserved"), then an own address,
    /// then `ignoreip`. An own address in `ignoreip` (a private host address
    /// in the default list) is named as an own address: that says more.
    fn exempt(&self, ip: Ipv4Addr) -> Option<Exempt> {
        if never_ban(ip) {
            Some(Exempt::Ignored)
        } else if self.own.contains(&ip) {
            Some(Exempt::Own)
        } else if self.ignore.iter().any(|net| net.contains(ip)) {
            Some(Exempt::Ignored)
        } else {
            None
        }
    }
}

/// A ban that waits to be applied.
#[derive(Clone, Debug, PartialEq)]
pub struct Pending {
    /// Host time of the failure that reached the threshold.
    pub ts: i64,
    pub count: usize,
    pub nvr: String,
    /// Already sanitised to printable ASCII.
    pub user: String,
}

/// What `next_ban` says about one address that `due` returned.
#[derive(Debug, PartialEq)]
pub enum Turn {
    /// Attempt this ban now, then tell the `Outcome`.
    Ban(Pending),
    /// The hourly allowance is used up: no more attempts in this poll.
    RateLimited,
    /// The ban no longer waits: go on with the next address.
    Gone,
}

/// How an attempt to apply a waiting ban ended.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Outcome {
    /// The firewall accepted the ban.
    Banned,
    /// Nothing was asked of the firewall: reported in notify-only mode or
    /// in a dry run. Counts like a ban.
    Reported,
    /// The address was already in the address-list. Uses no hourly
    /// allowance, and keeps the time of a ban the ledger already knows.
    AlreadyListed,
    /// The firewall refused the ban or could not be used: the ban keeps
    /// waiting.
    NotApplied,
}

/// How much the ledger holds, or (`Ledger::caps`) may hold.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sizes {
    /// Addresses with a failure counter.
    pub tracked: usize,
    /// Failure times of all addresses together.
    pub fail_times: usize,
    /// Failure times of the address with the most.
    pub most_fail_times: usize,
    /// Addresses remembered as banned (or reported).
    pub remembered: usize,
    /// Bans waiting to be applied.
    pub waiting: usize,
    /// Bans in the last hour.
    pub recent_bans: usize,
}

#[derive(Default, Debug, PartialEq)]
pub struct Ledger {
    /// Host times of recent failures per address.
    fails: BTreeMap<Ipv4Addr, Vec<i64>>,
    /// Host time until which an address counts as handled (banned, or
    /// reported in notify-only mode).
    banned: BTreeMap<Ipv4Addr, u64>,
    pending: BTreeMap<Ipv4Addr, Pending>,
    /// Host times of the bans applied in the last hour (the rate limit).
    recent_bans: Vec<u64>,
}

impl Ledger {
    /// Fits what was read from a state file to the rules in force. The
    /// state may come from a run with another `ignoreip`, or with a
    /// `maxretry` that kept more failure times.
    pub fn fit(&mut self, rules: &Rules) {
        self.drop_exempt(rules);
        let (cap, addresses) = fail_limits(rules.maxretry);
        for times in self.fails.values_mut() {
            if times.len() > cap {
                let extra = times.len() - cap;
                times.drain(..extra);
            }
        }
        self.forget_oldest(addresses);
    }

    /// Forgets the waiting ban and the counted failed logins of every
    /// address that is never banned. `failed_login` keeps such addresses
    /// out, but `ignoreip` may have changed since they were counted (a
    /// restart with a new config), or the address may have become an own
    /// address, and a waiting ban must not be applied then.
    fn drop_exempt(&mut self, rules: &Rules) {
        let mut addresses: Vec<Ipv4Addr> = self
            .pending
            .keys()
            .chain(self.fails.keys())
            .copied()
            .filter(|ip| rules.exempt(*ip).is_some())
            .collect();
        addresses.sort_unstable();
        addresses.dedup();
        for ip in addresses {
            let waiting = self.pending.remove(&ip).is_some();
            let counted = self.fails.remove(&ip).map_or(0, |times| times.len());
            let what = match (waiting, counted) {
                (true, 0) => "waiting ban dropped".to_string(),
                (true, n) => format!(
                    "waiting ban dropped, {} counted failed login(s) forgotten",
                    n
                ),
                (false, n) => format!("{} counted failed login(s) forgotten", n),
            };
            match rules.exempt(ip) {
                Some(Exempt::Own) => crate::info!(
                    "{}: {}: the address is now an own address of hik-f2b and is never banned",
                    ip,
                    what
                ),
                _ => crate::info!(
                    "{}: {}: the address is in ignoreip or a reserved range and is never banned",
                    ip,
                    what
                ),
            }
        }
    }

    /// Forgets the addresses whose last failure is the oldest until at most
    /// `keep` are tracked.
    fn forget_oldest(&mut self, keep: usize) {
        if self.fails.len() <= keep {
            return;
        }
        let mut by_age: Vec<(i64, Ipv4Addr)> = self
            .fails
            .iter()
            .map(|(ip, times)| (times.iter().copied().max().unwrap_or(0), *ip))
            .collect();
        by_age.sort_unstable();
        let extra = self.fails.len() - keep;
        for (_, ip) in by_age.into_iter().take(extra) {
            self.fails.remove(&ip);
        }
    }

    /// Remembers that `ip` is handled until `until` (see `banned`). With
    /// `MAX_BANNED` addresses remembered, the one whose end is nearest is
    /// forgotten first: it would be the next to expire anyway.
    fn remember_ban(&mut self, ip: Ipv4Addr, until: u64) {
        if !self.banned.contains_key(&ip) && self.banned.len() >= MAX_BANNED {
            let first = self
                .banned
                .iter()
                .min_by_key(|(ip, until)| (**until, **ip))
                .map(|(ip, _)| *ip);
            if let Some(first) = first {
                self.banned.remove(&first);
            }
        }
        self.banned.insert(ip, until);
    }

    /// Counts one failed login from `ip` at host time `ts` (`host_now` is
    /// the time of the poll), logged by the NVR `nvr` for the user name
    /// `user` (already sanitised). Once `maxretry` are counted within
    /// `findtime`, a ban waits. With `report_once` (no firewall, or a dry
    /// run) an address remembered as reported is not counted again.
    #[allow(clippy::too_many_arguments)]
    pub fn failed_login(
        &mut self,
        rules: &Rules,
        ip: Ipv4Addr,
        ts: i64,
        host_now: i64,
        nvr: &str,
        user: String,
        report_once: bool,
    ) {
        match rules.exempt(ip) {
            Some(Exempt::Own) => {
                crate::info!(
                    "{}: failed login from {} (user={:?}): an own address of hik-f2b, never \
                     banned, not counted; if that is hik-f2b's user, the NVR rejected hik-f2b's \
                     own login: check its password",
                    nvr,
                    ip,
                    user
                );
                return;
            }
            Some(Exempt::Ignored) => {
                crate::info!(
                    "{}: failed login from {} (user={:?}): never banned (ignoreip or reserved), not counted",
                    nvr,
                    ip,
                    user
                );
                return;
            }
            None => {}
        }
        if self.pending.contains_key(&ip) {
            return;
        }
        // Without a firewall (or in a dry run) nothing stops the address, so it
        // would be reported again with every burst; once per bantime (24 hours
        // for a permanent one) is enough.
        if report_once
            && self
                .banned
                .get(&ip)
                .is_some_and(|until| host_i64(*until) > host_now)
        {
            crate::info!(
                "{}: failed login from {} (user={:?}): already reported",
                nvr,
                ip,
                user
            );
            return;
        }
        let (cap, addresses) = fail_limits(rules.maxretry);
        if !self.fails.contains_key(&ip) && self.fails.len() >= addresses {
            // Forget the address whose last failure is the oldest.
            self.forget_oldest(addresses - 1);
        }
        let times = self.fails.entry(ip).or_default();
        times.push(ts);
        times.sort_unstable();
        let horizon = host_now.saturating_sub(rules.findtime);
        times.retain(|t| *t >= horizon);
        if times.len() > cap {
            let extra = times.len() - cap;
            times.drain(..extra);
        }
        let count = times.len();
        crate::info!(
            "{}: failed login from {} (user={:?}) at {} [{}/{}]",
            nvr,
            ip,
            user,
            util::fmt_ts(ts),
            count,
            rules.maxretry
        );
        if count >= rules.maxretry {
            self.queue(
                ip,
                Pending {
                    ts,
                    count,
                    nvr: nvr.to_string(),
                    user,
                },
            );
        }
    }

    /// Adds a waiting ban; with `MAX_PENDING` waiting, the oldest is
    /// dropped first.
    fn queue(&mut self, ip: Ipv4Addr, pending: Pending) {
        if self.pending.len() >= MAX_PENDING {
            let oldest = self
                .pending
                .iter()
                .min_by_key(|(ip, p)| (p.ts, **ip))
                .map(|(ip, _)| *ip);
            if let Some(oldest) = oldest {
                self.pending.remove(&oldest);
                crate::warn!(
                    "{} bans are already waiting; the oldest ({}) is dropped",
                    MAX_PENDING,
                    oldest
                );
            }
        }
        self.pending.insert(ip, pending);
    }

    /// The addresses whose bans are due at host time `now`, oldest first:
    /// the address that reached the threshold first has been waiting
    /// longest. Before that, the hourly rate window moves on, the waiting
    /// bans of exempt addresses are dropped, and so are the ones that
    /// waited longer than `bantime` (a day for a permanent ban). Ask
    /// `next_ban` for each in turn.
    pub fn due(&mut self, rules: &Rules, now: u64) -> Vec<Ipv4Addr> {
        // A ban time in the future can only come from the host clock having
        // been ahead; keep it as "now" so it still counts for an hour.
        for t in self.recent_bans.iter_mut() {
            *t = (*t).min(now);
        }
        self.recent_bans.retain(|t| now.saturating_sub(*t) < 3600);
        self.drop_exempt(rules);

        let bantime = rules.bantime;
        let keep = memory(bantime);
        let expired: Vec<Ipv4Addr> = self
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
            self.pending.remove(&ip);
        }

        let mut order: Vec<(i64, Ipv4Addr)> =
            self.pending.iter().map(|(ip, p)| (p.ts, *ip)).collect();
        order.sort_unstable();
        order.into_iter().map(|(_, ip)| ip).collect()
    }

    /// Whether the ban of `ip`, one of those `due` returned, is to be
    /// attempted now.
    pub fn next_ban(&self, rules: &Rules, ip: Ipv4Addr) -> Turn {
        let Some(p) = self.pending.get(&ip).cloned() else {
            return Turn::Gone;
        };
        // A safety valve: whatever goes wrong upstream, never flood the
        // router's address-list (or the chat).
        if self.recent_bans.len() >= rules.max_bans_per_hour {
            crate::warn!(
                "ban rate limit reached ({} per hour), {} address(es) are waiting",
                rules.max_bans_per_hour,
                self.pending.len()
            );
            return Turn::RateLimited;
        }
        Turn::Ban(p)
    }

    /// The host time the ban of `ip` began, as far as the ledger knows: the
    /// end it remembers, less what it keeps.
    pub fn ban_began(&self, rules: &Rules, ip: Ipv4Addr) -> Option<u64> {
        let keep = memory(rules.bantime);
        self.banned.get(&ip).map(|until| until.saturating_sub(keep))
    }

    /// Takes the outcome of the attempt to apply the waiting ban of `ip` at
    /// host time `now`.
    pub fn outcome(&mut self, rules: &Rules, ip: Ipv4Addr, now: u64, outcome: Outcome) {
        // whether it uses rate-limit allowance
        let counted = match outcome {
            Outcome::Banned | Outcome::Reported => true,
            Outcome::AlreadyListed => false,
            Outcome::NotApplied => return,
        };
        let keep = memory(rules.bantime);
        // Already listed: keep the time of the ban this ledger knows, if
        // any (an address listed by hand counts from now).
        if counted || !self.banned.contains_key(&ip) {
            self.remember_ban(ip, now.saturating_add(keep));
        }
        self.fails.remove(&ip);
        self.pending.remove(&ip);
        if counted {
            self.recent_bans.push(now);
        }
    }

    /// Forgets remembered bans that ended and failed logins outside
    /// `findtime`, at host time `host_now`.
    pub fn cleanup(&mut self, rules: &Rules, host_now: u64) {
        let keep = memory(rules.bantime);
        // An end further away than `keep` can only come from the host clock
        // having been ahead; such an entry would otherwise live for years.
        self.banned
            .retain(|_, until| *until > host_now && *until - host_now <= keep);
        let now = host_i64(host_now);
        let horizon = now.saturating_sub(rules.findtime);
        let future = now.saturating_add(MAX_FUTURE);
        self.fails.retain(|_, times| {
            times.retain(|t| *t >= horizon && *t <= future);
            !times.is_empty()
        });
    }

    /// The number of bans waiting.
    pub fn waiting(&self) -> usize {
        self.pending.len()
    }

    /// Whether a ban of `ip` waits.
    pub fn is_waiting(&self, ip: Ipv4Addr) -> bool {
        self.pending.contains_key(&ip)
    }

    /// The failed logins of `ip` that are counted.
    pub fn failed_logins(&self, ip: Ipv4Addr) -> usize {
        self.fails.get(&ip).map_or(0, Vec::len)
    }

    /// The host time until which `ip` is remembered as banned (or
    /// reported).
    pub fn banned_until(&self, ip: Ipv4Addr) -> Option<u64> {
        self.banned.get(&ip).copied()
    }

    /// How much the ledger holds.
    pub fn sizes(&self) -> Sizes {
        Sizes {
            tracked: self.fails.len(),
            fail_times: self.fails.values().map(Vec::len).sum(),
            most_fail_times: self.fails.values().map(Vec::len).max().unwrap_or(0),
            remembered: self.banned.len(),
            waiting: self.pending.len(),
            recent_bans: self.recent_bans.len(),
        }
    }

    /// How much the ledger holds at most, once `fit` to rules with this
    /// `maxretry` and `max_bans_per_hour`.
    pub fn caps(maxretry: usize, max_bans_per_hour: usize) -> Sizes {
        let (per_address, addresses) = fail_limits(maxretry);
        Sizes {
            tracked: addresses,
            fail_times: MAX_FAIL_TIMES,
            most_fail_times: per_address,
            remembered: MAX_BANNED,
            waiting: MAX_PENDING,
            recent_bans: max_bans_per_hour,
        }
    }

    /// Writes the ledger's lines of the state file.
    pub fn write_to(&self, out: &mut impl Write) -> std::io::Result<()> {
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

    /// Takes one line of a state file, split at spaces; false when it is
    /// not a ledger line or is not used (out of range, beyond a bound).
    pub(crate) fn read_line(&mut self, f: &[&str]) -> bool {
        match f {
            ["fail", ip, t] => {
                let (Ok(ip), Some(t)) = (ip.parse::<Ipv4Addr>(), time(t)) else {
                    return false;
                };
                if self.fails.len() >= MAX_TRACKED && !self.fails.contains_key(&ip) {
                    return false;
                }
                let times = self.fails.entry(ip).or_default();
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
                if self.banned.len() >= MAX_BANNED {
                    return false;
                }
                self.banned.insert(ip, until);
                true
            }
            ["pending", ip, ts, count, nvr, user @ ..] if util::is_name(nvr, 32) => {
                let count = count
                    .parse::<usize>()
                    .ok()
                    .filter(|c| (1..=1_000_000).contains(c));
                let (Ok(ip), Some(ts), Some(count)) = (ip.parse::<Ipv4Addr>(), time(ts), count)
                else {
                    return false;
                };
                if self.pending.len() >= MAX_PENDING {
                    return false;
                }
                self.pending.insert(
                    ip,
                    Pending {
                        ts,
                        count,
                        nvr: nvr.to_string(),
                        user: util::sanitize(&user.join(" "), MAX_USER),
                    },
                );
                true
            }
            ["rate", t] => {
                let Some(t) = utime(t) else {
                    return false;
                };
                if self.recent_bans.len() >= MAX_RATE {
                    return false;
                }
                self.recent_bans.push(t);
                true
            }
            _ => false,
        }
    }

    /// Ends the reading of a state file: puts the failure times in order.
    pub(crate) fn finish_reading(&mut self) {
        for times in self.fails.values_mut() {
            times.sort_unstable();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::State;
    use crate::util::{capture_log, captured_log};

    const T0: i64 = 1_768_000_000;
    const NO_IGNORE: &[Net] = &[];
    static NO_OWN: BTreeSet<Ipv4Addr> = BTreeSet::new();

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    /// Generated addresses, as in the end-to-end tests.
    fn address(i: usize) -> Ipv4Addr {
        Ipv4Addr::from(0x0B00_0000u32 + i as u32)
    }

    fn rules(ignore: &[Net]) -> Rules<'_> {
        Rules {
            maxretry: 3,
            findtime: 600,
            bantime: BanTime::Seconds(86400),
            max_bans_per_hour: 2,
            ignore,
            own: &NO_OWN,
        }
    }

    fn at(t: i64) -> u64 {
        t as u64
    }

    /// A ledger read from lines of a state file.
    fn read(lines: &str) -> Ledger {
        State::parse(&format!("hik-f2b-state 2\n{}", lines)).ledger
    }

    /// The ledger's lines of the state file.
    fn lines(ledger: &Ledger) -> String {
        let mut out = Vec::new();
        ledger.write_to(&mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    /// A failed login at host time `ts`, counted in the poll at `ts`.
    fn fail(ledger: &mut Ledger, rules: &Rules, ip: Ipv4Addr, ts: i64) {
        ledger.failed_login(rules, ip, ts, ts, "nvr1", "admin".to_string(), false);
    }

    /// `maxretry` failed logins of `ip`, the last at `ts`: a ban waits.
    fn make_waiting(ledger: &mut Ledger, rules: &Rules, ip: Ipv4Addr, ts: i64) {
        for k in (0..rules.maxretry).rev() {
            fail(ledger, rules, ip, ts - k as i64);
        }
        assert!(ledger.is_waiting(ip), "{}", ip);
    }

    fn pending(ts: i64, count: usize) -> Pending {
        Pending {
            ts,
            count,
            nvr: "nvr1".to_string(),
            user: "admin".to_string(),
        }
    }

    fn within(sizes: Sizes, caps: Sizes) -> bool {
        sizes.tracked <= caps.tracked
            && sizes.fail_times <= caps.fail_times
            && sizes.most_fail_times <= caps.most_fail_times
            && sizes.remembered <= caps.remembered
            && sizes.waiting <= caps.waiting
            && sizes.recent_bans <= caps.recent_bans
    }

    #[test]
    fn maxretry_failed_logins_within_findtime_make_a_ban_wait() {
        let r = rules(NO_IGNORE);
        let mut l = Ledger::default();
        let a = ip("198.51.100.7");
        capture_log();
        fail(&mut l, &r, a, T0);
        fail(&mut l, &r, a, T0 + 100);
        assert_eq!(l.failed_logins(a), 2);
        assert!(!l.is_waiting(a));
        // the first is exactly `findtime` before: still counted
        fail(&mut l, &r, a, T0 + 600);
        assert_eq!(l.failed_logins(a), 3);
        assert!(l.is_waiting(a));
        let log = captured_log();
        assert_eq!(log.len(), 3, "{:?}", log);
        assert_eq!(
            log[2],
            format!(
                "INFO nvr1: failed login from 198.51.100.7 (user=\"admin\") at {} [3/3]",
                util::fmt_ts(T0 + 600)
            )
        );
        assert_eq!(l.due(&r, at(T0 + 600)), vec![a]);
        assert_eq!(l.next_ban(&r, a), Turn::Ban(pending(T0 + 600, 3)));
    }

    #[test]
    fn failed_logins_outside_findtime_are_not_counted() {
        let r = rules(NO_IGNORE);
        let mut l = Ledger::default();
        let a = ip("198.51.100.7");
        fail(&mut l, &r, a, T0);
        fail(&mut l, &r, a, T0 + 300);
        // the first is now older than findtime
        fail(&mut l, &r, a, T0 + 601);
        assert_eq!(l.failed_logins(a), 2);
        assert!(!l.is_waiting(a));
        assert_eq!(l.waiting(), 0);
        fail(&mut l, &r, a, T0 + 700);
        assert_eq!(l.failed_logins(a), 3);
        assert!(l.is_waiting(a));
    }

    #[test]
    fn a_waiting_ban_counts_no_further_failed_logins() {
        let r = rules(NO_IGNORE);
        let mut l = Ledger::default();
        let a = ip("198.51.100.7");
        make_waiting(&mut l, &r, a, T0);
        capture_log();
        fail(&mut l, &r, a, T0 + 1);
        assert!(captured_log().is_empty());
        assert_eq!(l.failed_logins(a), 3);
        assert_eq!(l.next_ban(&r, a), Turn::Ban(pending(T0, 3)));
    }

    #[test]
    fn bans_are_attempted_oldest_first() {
        let r = rules(NO_IGNORE);
        let mut l = Ledger::default();
        make_waiting(&mut l, &r, ip("198.51.100.9"), T0 + 20);
        make_waiting(&mut l, &r, ip("198.51.100.8"), T0 + 10);
        make_waiting(&mut l, &r, ip("198.51.100.7"), T0 + 10);
        make_waiting(&mut l, &r, ip("198.51.100.6"), T0 + 30);
        assert_eq!(
            l.due(&r, at(T0 + 40)),
            vec![
                ip("198.51.100.7"),
                ip("198.51.100.8"),
                ip("198.51.100.9"),
                ip("198.51.100.6")
            ]
        );
    }

    #[test]
    fn an_applied_ban_is_remembered_and_uses_the_allowance() {
        let r = rules(NO_IGNORE);
        let mut l = Ledger::default();
        let a = ip("198.51.100.7");
        make_waiting(&mut l, &r, a, T0);
        assert_eq!(l.due(&r, at(T0 + 5)), vec![a]);
        l.outcome(&r, a, at(T0 + 5), Outcome::Banned);
        assert!(!l.is_waiting(a));
        assert_eq!(l.next_ban(&r, a), Turn::Gone);
        assert_eq!(l.failed_logins(a), 0);
        assert_eq!(l.banned_until(a), Some(at(T0 + 5 + 86400)));
        assert_eq!(l.ban_began(&r, a), Some(at(T0 + 5)));
        assert_eq!(l.sizes().recent_bans, 1);
    }

    #[test]
    fn an_address_already_listed_uses_no_allowance() {
        let r = rules(NO_IGNORE);
        let mut l = Ledger::default();
        // listed by hand: remembered from now
        let a = ip("198.51.100.7");
        make_waiting(&mut l, &r, a, T0);
        l.outcome(&r, a, at(T0 + 5), Outcome::AlreadyListed);
        assert!(!l.is_waiting(a));
        assert_eq!(l.failed_logins(a), 0);
        assert_eq!(l.banned_until(a), Some(at(T0 + 5 + 86400)));
        assert_eq!(l.ban_began(&r, a), Some(at(T0 + 5)));
        assert_eq!(l.sizes().recent_bans, 0);
        // banned by hik-f2b before: the time of that ban is kept
        let b = ip("198.51.100.8");
        make_waiting(&mut l, &r, b, T0);
        l.outcome(&r, b, at(T0 + 5), Outcome::Banned);
        make_waiting(&mut l, &r, b, T0 + 1000);
        l.outcome(&r, b, at(T0 + 1005), Outcome::AlreadyListed);
        assert_eq!(l.banned_until(b), Some(at(T0 + 5 + 86400)));
        assert_eq!(l.ban_began(&r, b), Some(at(T0 + 5)));
        assert_eq!(l.sizes().recent_bans, 1);
        // so the allowance is still there for one more
        let c = ip("198.51.100.9");
        make_waiting(&mut l, &r, c, T0 + 1000);
        assert_eq!(l.due(&r, at(T0 + 1010)), vec![c]);
        assert_eq!(l.next_ban(&r, c), Turn::Ban(pending(T0 + 1000, 3)));
    }

    #[test]
    fn a_refused_ban_keeps_waiting_and_uses_no_allowance() {
        let r = rules(NO_IGNORE);
        let mut l = Ledger::default();
        let a = ip("198.51.100.7");
        make_waiting(&mut l, &r, a, T0);
        for n in 0..5 {
            assert_eq!(l.due(&r, at(T0 + n)), vec![a]);
            assert_eq!(l.next_ban(&r, a), Turn::Ban(pending(T0, 3)));
            l.outcome(&r, a, at(T0 + n), Outcome::NotApplied);
        }
        assert!(l.is_waiting(a));
        assert_eq!(l.failed_logins(a), 3);
        assert_eq!(l.banned_until(a), None);
        assert_eq!(l.sizes().recent_bans, 0);
    }

    #[test]
    fn the_hourly_rate_limit_holds_bans_back() {
        let r = rules(NO_IGNORE);
        let mut l = Ledger::default();
        let (a, b, c) = (ip("198.51.100.1"), ip("198.51.100.2"), ip("198.51.100.3"));
        make_waiting(&mut l, &r, a, T0);
        make_waiting(&mut l, &r, b, T0 + 1);
        make_waiting(&mut l, &r, c, T0 + 2);
        assert_eq!(l.due(&r, at(T0 + 10)), vec![a, b, c]);
        for x in [a, b] {
            assert!(matches!(l.next_ban(&r, x), Turn::Ban(_)));
            l.outcome(&r, x, at(T0 + 10), Outcome::Banned);
        }
        capture_log();
        assert_eq!(l.next_ban(&r, c), Turn::RateLimited);
        assert_eq!(
            captured_log(),
            vec!["WARNING ban rate limit reached (2 per hour), 1 address(es) are waiting"]
        );
        // a reported address counts as a ban too
        let mut reported = Ledger::default();
        make_waiting(&mut reported, &r, a, T0);
        make_waiting(&mut reported, &r, b, T0);
        reported.outcome(&r, a, at(T0), Outcome::Reported);
        reported.outcome(&r, b, at(T0), Outcome::Reported);
        make_waiting(&mut reported, &r, c, T0);
        assert_eq!(reported.next_ban(&r, c), Turn::RateLimited);
        // until an hour has passed since the first ban
        assert_eq!(l.due(&r, at(T0 + 10 + 3599)), vec![c]);
        assert_eq!(l.next_ban(&r, c), Turn::RateLimited);
        assert_eq!(l.due(&r, at(T0 + 10 + 3600)), vec![c]);
        assert_eq!(l.sizes().recent_bans, 0);
        assert_eq!(l.next_ban(&r, c), Turn::Ban(pending(T0 + 2, 3)));
    }

    #[test]
    fn the_rate_limit_survives_a_save_and_load() {
        let r = rules(NO_IGNORE);
        let mut l = Ledger::default();
        let (a, b, c) = (ip("198.51.100.1"), ip("198.51.100.2"), ip("198.51.100.3"));
        for x in [a, b] {
            make_waiting(&mut l, &r, x, T0);
            l.outcome(&r, x, at(T0 + 10), Outcome::Banned);
        }
        make_waiting(&mut l, &r, c, T0);
        let text = lines(&l);
        assert!(
            text.ends_with(&format!("rate {}\nrate {}\n", T0 + 10, T0 + 10)),
            "{}",
            text
        );
        let mut loaded = read(&text);
        assert_eq!(loaded, l);
        assert_eq!(loaded.due(&r, at(T0 + 20)), vec![c]);
        assert_eq!(loaded.next_ban(&r, c), Turn::RateLimited);
    }

    #[test]
    fn a_timed_waiting_ban_expires_after_bantime() {
        let r = Rules {
            bantime: BanTime::Seconds(600),
            ..rules(NO_IGNORE)
        };
        let mut l = Ledger::default();
        let a = ip("198.51.100.7");
        make_waiting(&mut l, &r, a, T0);
        assert_eq!(l.due(&r, at(T0 + 600)), vec![a]);
        capture_log();
        assert!(l.due(&r, at(T0 + 601)).is_empty());
        assert_eq!(
            captured_log(),
            vec![
                "WARNING 198.51.100.7: the ban could not be applied within bantime (600 s) and \
                 is dropped"
            ]
        );
        assert_eq!(l.waiting(), 0);
        // what was counted stays until the cleanup forgets it
        assert_eq!(l.failed_logins(a), 3);
    }

    #[test]
    fn a_permanent_waiting_ban_expires_after_a_day() {
        let r = Rules {
            bantime: BanTime::Permanent,
            ..rules(NO_IGNORE)
        };
        let mut l = Ledger::default();
        let a = ip("198.51.100.7");
        make_waiting(&mut l, &r, a, T0);
        assert_eq!(l.due(&r, at(T0 + 86400)), vec![a]);
        capture_log();
        assert!(l.due(&r, at(T0 + 86401)).is_empty());
        assert_eq!(
            captured_log(),
            vec![
                "WARNING 198.51.100.7: the ban could not be applied within 86400 s and is dropped"
            ]
        );
        // a permanent ban is remembered for a day
        let b = ip("198.51.100.8");
        make_waiting(&mut l, &r, b, T0);
        l.outcome(&r, b, at(T0), Outcome::Banned);
        assert_eq!(l.banned_until(b), Some(at(T0 + 86400)));
        assert_eq!(l.ban_began(&r, b), Some(at(T0)));
    }

    #[test]
    fn exempt_addresses_are_never_counted() {
        let ignore = [Net::parse("203.0.113.16/29").unwrap()];
        let r = rules(&ignore);
        let mut l = Ledger::default();
        capture_log();
        fail(&mut l, &r, ip("203.0.113.17"), T0);
        assert_eq!(
            captured_log(),
            vec![
                "INFO nvr1: failed login from 203.0.113.17 (user=\"admin\"): never banned \
                 (ignoreip or reserved), not counted"
            ]
        );
        let reserved = [
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(169, 254, 0, 1),
            Ipv4Addr::new(0, 1, 2, 3),
            Ipv4Addr::new(240, 0, 0, 1),
        ];
        for x in reserved.into_iter().chain([ip("203.0.113.23")]) {
            for k in 0..3 {
                fail(&mut l, &r, x, T0 + k);
            }
            assert_eq!(l.failed_logins(x), 0, "{}", x);
            assert!(!l.is_waiting(x), "{}", x);
        }
        assert_eq!(l.sizes(), Sizes::default());
        // just outside ignoreip
        make_waiting(&mut l, &r, ip("203.0.113.24"), T0);
    }

    #[test]
    fn addresses_that_became_exempt_are_dropped() {
        let text = format!(
            "fail 198.51.100.7 {t}\n\
             fail 203.0.113.17 {t}\nfail 203.0.113.17 {t}\nfail 203.0.113.17 {t}\n\
             fail 203.0.113.18 {t}\n\
             pending 203.0.113.17 {t} 3 nvr1 admin\npending 203.0.113.19 {t} 3 nvr1 admin\n",
            t = T0
        );
        let ignore = [Net::parse("203.0.113.16/29").unwrap()];
        let r = rules(&ignore);
        let expected = vec![
            "INFO 203.0.113.17: waiting ban dropped, 3 counted failed login(s) forgotten: the \
             address is in ignoreip or a reserved range and is never banned",
            "INFO 203.0.113.18: 1 counted failed login(s) forgotten: the address is in ignoreip \
             or a reserved range and is never banned",
            "INFO 203.0.113.19: waiting ban dropped: the address is in ignoreip or a reserved \
             range and is never banned",
        ];
        // at the start
        let mut l = read(&text);
        assert_eq!(l.waiting(), 2);
        capture_log();
        l.fit(&r);
        assert_eq!(captured_log(), expected);
        assert_eq!(l.waiting(), 0);
        assert_eq!(l.sizes().tracked, 1);
        assert_eq!(l.failed_logins(ip("198.51.100.7")), 1);
        // and before bans are attempted
        let mut l = read(&text);
        capture_log();
        assert!(l.due(&r, at(T0 + 10)).is_empty());
        assert_eq!(captured_log(), expected);
        assert_eq!(l.sizes().tracked, 1);
    }

    /// An own address is exempt wherever an address in `ignoreip` is: a
    /// failed login is not counted, and a waiting ban and counted failed
    /// logins are dropped at the start and before bans are attempted.
    #[test]
    fn own_addresses_are_exempt_like_ignoreip() {
        let own: BTreeSet<Ipv4Addr> = [ip("192.0.2.200")].into();
        let r = Rules {
            own: &own,
            ..rules(NO_IGNORE)
        };
        let mut l = Ledger::default();
        capture_log();
        for k in 0..5 {
            l.failed_login(
                &r,
                ip("192.0.2.200"),
                T0 + k,
                T0 + k,
                "nvr1",
                "f2b".into(),
                false,
            );
        }
        let log = captured_log();
        assert_eq!(log.len(), 5);
        assert_eq!(
            log[0],
            "INFO nvr1: failed login from 192.0.2.200 (user=\"f2b\"): an own address of \
             hik-f2b, never banned, not counted; if that is hik-f2b's user, the NVR rejected \
             hik-f2b's own login: check its password"
        );
        assert_eq!(l.sizes(), Sizes::default());
        // also in notify-only mode and in a dry run
        l.failed_login(&r, ip("192.0.2.200"), T0, T0, "nvr1", "f2b".into(), true);
        assert_eq!(l.sizes(), Sizes::default());
        // an own address in ignoreip is named as an own address; a reserved
        // one keeps its line
        let ignore = [Net::parse("192.0.2.0/24").unwrap()];
        let both: BTreeSet<Ipv4Addr> = [ip("192.0.2.200"), Ipv4Addr::LOCALHOST].into();
        let r2 = Rules {
            own: &both,
            ..rules(&ignore)
        };
        capture_log();
        fail(&mut l, &r2, ip("192.0.2.200"), T0);
        fail(&mut l, &r2, Ipv4Addr::LOCALHOST, T0);
        fail(&mut l, &r2, ip("192.0.2.201"), T0);
        let log = captured_log();
        assert!(log[0].contains("an own address of hik-f2b"), "{}", log[0]);
        assert!(log[1].ends_with("never banned (ignoreip or reserved), not counted"));
        assert!(log[2].ends_with("never banned (ignoreip or reserved), not counted"));
        // just another address: counted
        fail(&mut l, &r, ip("192.0.2.201"), T0);
        assert_eq!(l.failed_logins(ip("192.0.2.201")), 1);

        // an address that became an own address
        let text = format!(
            "fail 192.0.2.200 {t}\nfail 192.0.2.200 {t}\nfail 192.0.2.200 {t}\n\
             fail 192.0.2.201 {t}\nfail 198.51.100.7 {t}\n\
             pending 192.0.2.200 {t} 3 nvr1 admin\npending 192.0.2.202 {t} 3 nvr1 admin\n",
            t = T0
        );
        let own: BTreeSet<Ipv4Addr> =
            [ip("192.0.2.200"), ip("192.0.2.201"), ip("192.0.2.202")].into();
        let r = Rules {
            own: &own,
            ..rules(NO_IGNORE)
        };
        let expected = vec![
            "INFO 192.0.2.200: waiting ban dropped, 3 counted failed login(s) forgotten: the \
             address is now an own address of hik-f2b and is never banned",
            "INFO 192.0.2.201: 1 counted failed login(s) forgotten: the address is now an own \
             address of hik-f2b and is never banned",
            "INFO 192.0.2.202: waiting ban dropped: the address is now an own address of hik-f2b \
             and is never banned",
        ];
        // at the start
        let mut l = read(&text);
        capture_log();
        l.fit(&r);
        assert_eq!(captured_log(), expected);
        assert_eq!(l.waiting(), 0);
        assert_eq!(l.sizes().tracked, 1);
        // and before bans are attempted (the re-check before a ban)
        let mut l = read(&text);
        assert_eq!(l.due(&rules(NO_IGNORE), at(T0 + 10)).len(), 2);
        capture_log();
        assert!(l.due(&r, at(T0 + 10)).is_empty());
        assert_eq!(captured_log(), expected);
        assert_eq!(l.next_ban(&r, ip("192.0.2.200")), Turn::Gone);
        assert_eq!(l.failed_logins(ip("198.51.100.7")), 1);
    }

    #[test]
    fn a_host_clock_that_went_back() {
        let r = Rules {
            max_bans_per_hour: 1,
            ..rules(NO_IGNORE)
        };
        // a ban time in the future counts as now, for an hour
        let mut l = read(&format!("rate {}\n", T0 + 5000));
        let a = ip("198.51.100.7");
        make_waiting(&mut l, &r, a, T0 - 10);
        assert_eq!(l.due(&r, at(T0)), vec![a]);
        assert_eq!(l.next_ban(&r, a), Turn::RateLimited);
        assert!(lines(&l).ends_with(&format!("rate {}\n", T0)));
        assert_eq!(l.due(&r, at(T0 + 3599)), vec![a]);
        assert_eq!(l.next_ban(&r, a), Turn::RateLimited);
        assert_eq!(l.due(&r, at(T0 + 3600)), vec![a]);
        assert!(matches!(l.next_ban(&r, a), Turn::Ban(_)));
        // a waiting ban from the future is not dropped as expired
        let mut l = read(&format!(
            "pending 198.51.100.8 {} 3 nvr1 admin\n",
            T0 + 100_000
        ));
        assert_eq!(l.due(&r, at(T0)), vec![ip("198.51.100.8")]);
        // a remembered ban that ends further away than bantime is forgotten
        let mut l = read(&format!(
            "ban 198.51.100.8 {}\nban 198.51.100.9 {}\n",
            T0 + 86400,
            T0 + 86401
        ));
        l.cleanup(&r, at(T0));
        assert_eq!(l.banned_until(ip("198.51.100.8")), Some(at(T0 + 86400)));
        assert_eq!(l.banned_until(ip("198.51.100.9")), None);
        // so are failed logins too far in the future
        let mut l = read(&format!(
            "fail 198.51.100.10 {}\nfail 198.51.100.11 {}\n",
            T0 + MAX_FUTURE,
            T0 + MAX_FUTURE + 1
        ));
        l.cleanup(&r, at(T0));
        assert_eq!(l.failed_logins(ip("198.51.100.10")), 1);
        assert_eq!(l.failed_logins(ip("198.51.100.11")), 0);
    }

    /// Notify-only mode and dry runs (`report_once`): an address is
    /// reported once while it is remembered.
    #[test]
    fn a_reported_address_is_not_counted_again_while_remembered() {
        let r = rules(NO_IGNORE);
        let mut l = Ledger::default();
        let a = ip("198.51.100.7");
        make_waiting(&mut l, &r, a, T0);
        l.outcome(&r, a, at(T0), Outcome::Reported);
        assert_eq!(l.banned_until(a), Some(at(T0 + 86400)));
        assert_eq!(l.sizes().recent_bans, 1);
        assert_eq!(l.failed_logins(a), 0);
        capture_log();
        l.failed_login(&r, a, T0 + 10, T0 + 10, "nvr1", "admin".to_string(), true);
        assert_eq!(
            captured_log(),
            vec!["INFO nvr1: failed login from 198.51.100.7 (user=\"admin\"): already reported"]
        );
        assert_eq!(l.failed_logins(a), 0);
        // with a firewall it would be counted
        fail(&mut l, &r, a, T0 + 10);
        assert_eq!(l.failed_logins(a), 1);
        // and once the time it is remembered for is over, it is reported
        // again
        let at_end = T0 + 86400;
        l.failed_login(&r, a, at_end, at_end, "nvr1", "admin".to_string(), true);
        assert_eq!(l.failed_logins(a), 1);
        l.failed_login(&r, a, at_end, at_end, "nvr1", "admin".to_string(), true);
        l.failed_login(&r, a, at_end, at_end, "nvr1", "admin".to_string(), true);
        assert!(l.is_waiting(a));
    }

    #[test]
    fn the_cleanup_forgets_ended_bans_and_old_failed_logins() {
        let r = rules(NO_IGNORE);
        let mut l = read(&format!(
            "fail 198.51.100.1 {}\nfail 198.51.100.2 {}\nfail 198.51.100.2 {}\n\
             ban 198.51.100.3 {}\nban 198.51.100.4 {}\n",
            T0 - 601,
            T0 - 601,
            T0 - 600,
            T0,
            T0 + 1
        ));
        l.cleanup(&r, at(T0));
        assert_eq!(l.failed_logins(ip("198.51.100.1")), 0);
        assert_eq!(l.failed_logins(ip("198.51.100.2")), 1);
        assert_eq!(l.sizes().tracked, 1);
        assert_eq!(l.banned_until(ip("198.51.100.3")), None);
        assert_eq!(l.banned_until(ip("198.51.100.4")), Some(at(T0 + 1)));
    }

    /// Loading a state file and inserting give the same bounds: a ledger
    /// read from a file and fit to the rules holds no more than one filled
    /// by failed logins and bans.
    #[test]
    fn loading_and_inserting_enforce_the_same_caps() {
        let r = Rules {
            findtime: 1_000_000,
            ..rules(NO_IGNORE)
        };
        let caps = Ledger::caps(r.maxretry, r.max_bans_per_hour);
        assert_eq!(caps.most_fail_times, 16);
        assert_eq!(caps.tracked, MAX_TRACKED);

        // waiting bans: the line beyond the bound is ignored...
        let text: String = (0..MAX_PENDING)
            .map(|i| format!("pending {} {} 3 nvr1 admin\n", address(i), T0 + i as i64))
            .collect();
        let extra = format!(
            "pending {} {} 3 nvr1 admin\n",
            address(MAX_PENDING),
            T0 + 5000
        );
        let l = read(&(text.clone() + &extra));
        assert_eq!(l.waiting(), MAX_PENDING);
        assert!(!l.is_waiting(address(MAX_PENDING)));
        // ...and a new one drops the oldest
        let mut l = read(&text);
        capture_log();
        make_waiting(&mut l, &r, address(MAX_PENDING), T0 + 5000);
        assert_eq!(l.waiting(), MAX_PENDING);
        assert!(!l.is_waiting(address(0)));
        assert!(l.is_waiting(address(1)));
        assert!(captured_log().contains(&format!(
            "WARNING {} bans are already waiting; the oldest ({}) is dropped",
            MAX_PENDING,
            address(0)
        )));

        // remembered bans: the same
        let text: String = (0..MAX_BANNED)
            .map(|i| format!("ban {} {}\n", address(i), T0 + 1000 + i as i64))
            .collect();
        let extra = format!("ban {} {}\n", address(MAX_BANNED), T0 + 5000);
        let l = read(&(text.clone() + &extra));
        assert_eq!(l.sizes().remembered, MAX_BANNED);
        assert_eq!(l.banned_until(address(MAX_BANNED)), None);
        let mut l = read(&text);
        let a = ip("198.51.100.7");
        make_waiting(&mut l, &r, a, T0);
        l.outcome(&r, a, at(T0), Outcome::Banned);
        assert_eq!(l.sizes().remembered, MAX_BANNED);
        assert!(l.banned_until(a).is_some());
        // the one whose end is nearest is forgotten
        assert_eq!(l.banned_until(address(0)), None);
        assert!(l.banned_until(address(1)).is_some());
        assert!(within(l.sizes(), caps));

        // failure times of one address: what a file holds is cut down to
        // what failed logins can fill
        let text = format!("fail 198.51.100.7 {}\n", T0).repeat(5000);
        let mut l = read(&text);
        assert_eq!(l.failed_logins(a), MAX_TIMES);
        l.fit(&r);
        assert_eq!(l.failed_logins(a), caps.most_fail_times);
        // and so does a failed login counted on top of them
        let mut l = read(&text);
        fail(&mut l, &r, a, T0 + 1);
        assert_eq!(l.failed_logins(a), caps.most_fail_times);
        assert!(l.is_waiting(a));

        // tracked addresses: with maxretry 100 only 500 are kept
        let r = Rules { maxretry: 100, ..r };
        let caps = Ledger::caps(r.maxretry, r.max_bans_per_hour);
        assert_eq!((caps.tracked, caps.most_fail_times), (500, 400));
        let text: String = (0..=MAX_TRACKED)
            .map(|i| format!("fail {} {}\n", address(i), T0 + i as i64))
            .collect();
        let mut l = read(&text);
        assert_eq!(l.sizes().tracked, MAX_TRACKED);
        l.fit(&r);
        assert_eq!(l.sizes().tracked, caps.tracked);
        // the newest stay
        assert_eq!(l.failed_logins(address(MAX_TRACKED - 1)), 1);
        assert_eq!(l.failed_logins(address(MAX_TRACKED - 500)), 1);
        assert_eq!(l.failed_logins(address(MAX_TRACKED - 501)), 0);
        assert!(within(l.sizes(), caps));
        // a new address makes the one with the oldest failed login go
        let b = ip("198.51.100.8");
        fail(&mut l, &r, b, T0 + 20_000);
        assert_eq!(l.sizes().tracked, caps.tracked);
        assert_eq!(l.failed_logins(b), 1);
        assert_eq!(l.failed_logins(address(MAX_TRACKED - 500)), 0);
        assert!(within(l.sizes(), caps));
    }

    #[test]
    fn the_ledger_lines_are_written_and_read_back() {
        let r = rules(NO_IGNORE);
        let mut l = Ledger::default();
        let (a, b, c) = (ip("198.51.100.1"), ip("198.51.100.2"), ip("198.51.100.3"));
        make_waiting(&mut l, &r, a, T0);
        l.outcome(&r, a, at(T0 + 5), Outcome::Banned);
        make_waiting(&mut l, &r, b, T0 + 1);
        l.failed_login(
            &r,
            c,
            T0 + 2,
            T0 + 2,
            "nvr2",
            "no such user".to_string(),
            false,
        );
        let text = lines(&l);
        assert_eq!(
            text,
            format!(
                "fail 198.51.100.2 {}\nfail 198.51.100.2 {}\nfail 198.51.100.2 {}\n\
                 fail 198.51.100.3 {}\n\
                 ban 198.51.100.1 {}\n\
                 pending 198.51.100.2 {} 3 nvr1 admin\n\
                 rate {}\n",
                T0 - 1,
                T0,
                T0 + 1,
                T0 + 2,
                T0 + 5 + 86400,
                T0 + 1,
                T0 + 5
            )
        );
        let loaded = read(&text);
        assert_eq!(loaded, l);
        assert_eq!(lines(&loaded), text);
    }
}
