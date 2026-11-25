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
use std::collections::BTreeMap;
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
fn never_ban(ip: Ipv4Addr) -> bool {
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
}

impl<'a> Rules<'a> {
    pub fn of(cfg: &'a Config) -> Rules<'a> {
        Rules {
            maxretry: cfg.maxretry,
            findtime: cfg.findtime,
            bantime: cfg.bantime,
            max_bans_per_hour: cfg.max_bans_per_hour,
            ignore: &cfg.ignore,
        }
    }

    /// Never banned: in `ignoreip`, or in a range `never_ban` names.
    fn exempt(&self, ip: Ipv4Addr) -> bool {
        never_ban(ip) || self.ignore.iter().any(|net| net.contains(ip))
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

#[derive(Default, Debug, PartialEq)]
pub struct Ledger {
    /// Host times of recent failures per address.
    pub fails: BTreeMap<Ipv4Addr, Vec<i64>>,
    /// Host time until which an address counts as handled (banned, or
    /// reported in notify-only mode).
    pub banned: BTreeMap<Ipv4Addr, u64>,
    pub pending: BTreeMap<Ipv4Addr, Pending>,
    /// Host times of the bans applied in the last hour (the rate limit).
    pub recent_bans: Vec<u64>,
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
    /// restart with a new config), and a waiting ban must not be applied
    /// then.
    fn drop_exempt(&mut self, rules: &Rules) {
        let mut addresses: Vec<Ipv4Addr> = self
            .pending
            .keys()
            .chain(self.fails.keys())
            .copied()
            .filter(|ip| rules.exempt(*ip))
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
            crate::info!(
                "{}: {}: the address is in ignoreip or a reserved range and is never banned",
                ip,
                what
            );
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
        if rules.exempt(ip) {
            crate::info!(
                "{}: failed login from {} (user={:?}): never banned (ignoreip or reserved), not counted",
                nvr,
                ip,
                user
            );
            return;
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
                        user: util::sanitize(&user.join(" "), 64),
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
