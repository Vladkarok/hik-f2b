//! A deterministic randomized simulation of the engine against the fakes in
//! `support/fake.rs`: generated scenarios drive the real engine (HTTP to the
//! fake NVRs, router and Telegram, host time injected with `cycle_at`), and
//! invariants are checked after every cycle and at the end of each scenario.
//!
//! A scenario is drawn from one seed with a small xorshift generator. The
//! seed also picks the scenario class (`seed % 5`):
//!
//! - `Firewall`: bans go to the router. Failed logins from persistent and
//!   occasional attackers (RFC 5737 addresses), from the owner's network
//!   (`203.0.113.16/29`, exempt or not), from private addresses, and odd
//!   entries (IPv4-mapped IPv6, IPv6, no address, a malformed address,
//!   another log type). Polls at regular and irregular intervals. The router
//!   reachable, unreachable (transport error) or refusing writes while reads
//!   work, and addresses listed by hand ("already listed"); a listed address
//!   mostly stops reaching the NVR. Restarts with the saved state, with the
//!   same config or with `ignoreip` changed (the owner's network or one
//!   attacker added or removed). NVRs unreachable or answering with an
//!   unreadable page for a while, listing newest or oldest first. Timed and
//!   permanent `bantime`, small and large `max_bans_per_hour`.
//! - `Backlog`: as `Firewall`, plus floods: thousands of entries (other log
//!   types and private addresses, with attackers among them) logged while
//!   hik-f2b does not poll, so that one window holds more than one search
//!   returns, read newest first or oldest first.
//! - `DryRun` and `NotifyOnly`: as `Firewall` with `dry_run = true`, and
//!   without a router.
//! - `Clock`: as `Firewall`, plus device clock steps: forward and backward,
//!   below and above the thresholds the engine treats as a jump, a DST
//!   change, an RTC reset to 2000-01-01 and its correction, and the end of
//!   DST on an NVR that cannot be reached for an hour while failed logins
//!   are logged (they are read only after the step).
//!
//! Every class also has failed logins from the host's own address (`OWN`,
//! the address the harness reaches every device from): with hik-f2b's user
//! name, as after its NVR password was changed, or with another one, as a
//! forged entry would have. In the classes with a router, `OWN` is also put
//! into the address-list by an outside hand now and then.
//!
//! In the classes with a router, half of the scenarios have the safe list
//! `SAFE` (`safe_list`), four in five of them with its accept rule above the
//! drop rule. Whether a scenario has them is drawn from a generator of its
//! own, so a seed gives the same events with and without them. The fake
//! router expires an entry of the safe list when its timeout has passed.
//!
//! Half of the scenarios, in every class, have the host name `NAME` in
//! `ignoreip`, whose fixed answer (`own::Fixed`) gives one or both of the
//! addresses `NAMED`, no IPv4 address, or a failed look-up, and changes now
//! and then during the scenario. Those scenarios also have failed logins from
//! the `NAMED` addresses and, with a router, those addresses put into the
//! address-list by hand. Whether a scenario has the name, and all of these
//! events, are drawn from a generator of their own, so a seed gives the same
//! other events with and without it. The model learns what the name
//! resolves to for the engine from the look-ups that reach the fixed
//! answers, as the fake router shows what the engine asked of it.
//!
//! Every scenario starts with failed logins already in the logs (some within
//! `lookback` before the first start), may start with an NVR unreachable, and
//! ends with a settle phase: router and NVRs back, then polls until no ban is
//! waiting.
//!
//! Invariants, and the classes they are exact for:
//!
//! - `safety/exempt` (all): no ban request, report, ban notification or
//!   counted failed login for an address that is exempt (`ignoreip` in force
//!   at that moment, a range that is never banned, or the own address `OWN`).
//!   Exemption is computed here, not by the engine.
//! - `own/other` (all): only `OWN` is ever said to be an own address of
//!   hik-f2b: no address read from a log becomes one.
//! - `safety/maxretry` (all): every ban request or report for an address is
//!   backed by `maxretry` failed logins of it, logged after its NVR's first
//!   start, within a `findtime` span (true host time, from the generated
//!   log). The span may be longer by the largest shift of a failed login of
//!   that address that was counted: the host time the engine counted it at
//!   minus its true host time. A shift other than 0 needs a device clock
//!   step that is not a resync (`Clock` only): an entry logged before such a
//!   step and read after it is converted with the new offset. (A counted
//!   entry is at most `findtime` before the poll that counts it, in the
//!   engine's time, and every entry is logged before that poll in true time;
//!   so its true time is at most `findtime` plus its shift before the poll.)
//! - `safety/rate` (all): at most `max_bans_per_hour` bans and reports in
//!   any hour, across restarts.
//! - `state` (all): the state loads back from its file format to the same
//!   state after every cycle (and through the file on every restart);
//!   `caps` (all): the bounded collections stay within their bounds.
//! - `panic` (all): no panic.
//! - `count/prestart`, `count/double` (all): each failed login counted (the
//!   engine's `[n/maxretry]` log line) matches a generated one of the same
//!   NVR, address and device time, logged after the first start, at most
//!   once. The device time is the counted host time plus the offset the
//!   engine read at that poll (the fake's skew); several entries share a
//!   device time only after a device clock went back, and then at most as
//!   many are counted as were logged.
//! - `count/shift` (all): a failed login is counted at a host time that
//!   differs from its true host time by at most what the engine allows:
//!   `CLOCK_JUMP` for each change of the NVR's offset the engine stored
//!   between the entry's logging and its count, plus how far the device
//!   clock was from the stored offset when the entry was logged (a step
//!   between two polls that is undone before the next one cannot be seen).
//!   An offset change larger than `CLOCK_JUMP`, in either direction, must be
//!   a resync, after which nothing logged before it is counted.
//! - `liveness` (all but `Clock`): after the settle phase, every address
//!   that is never exempt and had `maxretry` failed logins that the engine
//!   must have read within `findtime` of the first of them has been banned
//!   (or found already listed) at or after that first one; in `DryRun` and
//!   `NotifyOnly` it has been reported, at the latest `bantime` before it
//!   (reports are once per `bantime`). "Must have read" is a conservative
//!   bound: the poll that reads an entry is at the latest the first
//!   successful poll after it, plus one poll per `PER_POLL` entries logged
//!   on that NVR in the `findtime + lookback` before it (an oldest-first NVR
//!   reads a backlog over several polls). Documented losses are excluded:
//!   entries in a stretch reported as SKIPPING or "within one second", and
//!   addresses whose waiting ban was dropped after `bantime`.
//! - `liveness/once` (all): reports of an address at least `bantime` (24 h
//!   for a permanent one) apart; accepted bans of an address at least
//!   `bantime` apart (the fake router expires timed entries), and at most
//!   one for a permanent ban.
//! - `notify` (all): one ban notification for each ban and report, none for
//!   an address that is already listed.
//! - `own/removed` (`Firewall`, `Backlog`, `Clock`): after each firewall
//!   check that the router answers (at an engine start, and the periodic one
//!   in a cycle), `OWN` is not in the address-list if the router accepts
//!   writes, and each removal is one WARNING. While the router refuses
//!   writes it stays listed, with an ERROR at each such check. `own/kept`
//!   (`DryRun`): `OWN` is never removed, and a check that finds it listed
//!   reports it (a WARNING), once while it stays listed. `own/notify` (all
//!   with a router): one notification at once for each removal, and one for
//!   each stretch in which `OWN` stays listed after a check that answered
//!   (dry run, or refused), sent at the end of the cycle (or of the first
//!   cycle after an engine start); none else. No other request about `OWN`
//!   fails while the router answers its checks. `own/only` (all): every
//!   request to remove an address-list entry is for `OWN`, and the router
//!   removes one only where a removal is logged.
//! - `safe/only` (all with a router): every write to the safe list is for
//!   `OWN`, to `SAFE`, and the safe list never holds anything else.
//!   `safe/off` (all): without `safe_list`, no write to any list but the
//!   address-list, no request that names another list or reads a whole
//!   table of rules, no `PATCH`, and no line about a safe list.
//!   `safe/dry` (`DryRun`): nothing is written to the safe list, and the
//!   first check that the router answers after each engine start says what
//!   it would write (one line), no later one. `safe/kept` (`Firewall`,
//!   `Backlog`, `Clock`): at each firewall check that the router answers,
//!   one write for `OWN`: an entry that is there is renewed, one that is
//!   not is added (never a duplicate); while the router refuses writes, it
//!   is refused with an ERROR. After a check that the router answers and
//!   that is not refused, `OWN` has one entry, with a timeout that outlives
//!   three checks. No write in a check that the router does not answer,
//!   and none between checks. The rule check fails (one line) at each such
//!   check exactly when the scenario has no accept rule.
//! - `name/exempt` (all): no ban request, report, ban notification or
//!   counted failed login for an address while the name resolves to it for
//!   the engine running now: what the last look-up of that engine that found
//!   an IPv4 address answered. `name/line` (all): a failed login said to be
//!   exempt for an `ignoreip` name, and a waiting ban or counted failed
//!   logins dropped for one, are of such an address and name `NAME`; without
//!   the name, no line names an `ignoreip` name. `name/kept` (all with a
//!   router): an address the name resolves to, or once did, that is in the
//!   address-list before a cycle or an engine start is still there after it:
//!   hik-f2b removes nothing for it. `name/interval` (all with the name):
//!   the name is looked up once at each engine start, not at the first poll
//!   after it, and then exactly at the first poll `RESOLVE_EVERY` or more
//!   after the last look-up (the first poll for the one at the start).
//!   `name/log` (all with the name): the start of an engine says what the
//!   name resolves to (one line) and, if it does not resolve, a WARNING;
//!   a look-up that changes what it resolves to is one INFO line with the new
//!   and old addresses, the first that fails after one that worked is one
//!   WARNING, the first that works after failures and changes nothing is one
//!   INFO line, and no other line is about the name.
//! - `health/model` (all): the health notices of each cycle are exactly the
//!   ones the documented policy gives for what the engine observed (failed
//!   and successful polls, ban attempts, firewall checks, the rate limit,
//!   listed addresses that still reach an NVR well after their ban, which
//!   is over once none has for `alert_after` while every NVR is read; none
//!   is such an address within `STARTUP_GRACE` after an engine start; an own
//!   address that a check that answered finds listed and cannot remove,
//!   which is over at the first such check that leaves none listed; with
//!   the safe list, the missing rule at each check that answered, and a
//!   write the router refuses, which only a write that works ends; a
//!   firewall that only a failed ban found unusable, which a check that
//!   works ends only after a check failed, and otherwise withdraws once no
//!   ban waits, while a ban that the router answers ends it):
//!   alert once after `alert_after`, reminder after 24 h, one recovery or
//!   "unknown" when an alerted problem ends, nothing for a short one, state
//!   lost on restart. `health/condition` (all): an unreachable firewall is
//!   observed only while the router is unreachable, a refused ban only while
//!   it refuses writes. `health/stretch` (`Firewall`, `Backlog`): when the
//!   router keeps a waiting ban from being applied for `alert_after`
//!   (unreachable, or refusing), the alert has been sent by the first cycle
//!   after that.
//! - `start/count` (all): an engine start whose firewall check the router
//!   answered ends with one request for the entries of the address-list
//!   (the last request of the start) and one INFO line with their number,
//!   as many as the fake router holds; a start whose check it did not
//!   answer (or without a router), and a cycle, have neither.
//!
//! `liveness` is not checked in `Clock`: a resync after a clock change
//! leaves out what was logged around it, by design.
//!
//! Environment: `HIK_F2B_SIM_SEEDS` (seeds per class, default
//! `DEFAULT_SEEDS`, fewer for `Backlog`), `HIK_F2B_SIM_START` (first seed, default 1),
//! `HIK_F2B_SIM_SEED` (run only that seed, in its class, and print its
//! trace). A violation prints the seed, the class, the parameters and the
//! last steps of the trace.
//!
//! The summary line of each class also gives the peak number of threads of
//! the fakes in the process (of all classes together). Above
//! `MAX_FAKE_THREADS` the class fails: a fault of the test harness.
//! Failed accepts on the fakes' listeners fail the class too.
//!
//! On Linux the line also gives the most entries seen in the kernel's
//! connection tracking table (`fake::conntrack`). Each loopback connection
//! takes one for two minutes, and a long run makes thousands a second.
//! When the table is full, the kernel drops new connections: requests to
//! the fakes time out and the results do not hold. The class then fails
//! with that cause, a fault of the environment; `sim.yml` takes loopback
//! out of the tracking.

#[path = "support/fake.rs"]
mod fake;

use fake::{Entry, Fake, Harness, Opts, SKEW};
use hik_f2b::ledger::Ledger;
use hik_f2b::names::RESOLVE_EVERY;
use hik_f2b::reader::{CLOCK_JUMP, MAX_SEEN};
use hik_f2b::state::State;
use hik_f2b::util;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Seeds per class when `HIK_F2B_SIM_SEEDS` is not set (`Backlog`: a third).
const DEFAULT_SEEDS: u64 = 30;
/// The most threads the fakes may have at once in the process (listeners
/// and connections, see `fake::live_threads`). The five classes run at the
/// same time, each with one harness at a time of at most two fakes. The
/// bound does not grow with the number of seeds, so harnesses that leave
/// threads behind exceed it.
const MAX_FAKE_THREADS: usize = 60;
/// Whether a violation fails the test (otherwise it is only printed).
const STRICT: bool = true;
/// Trace lines shown with a violation.
const TRACE_LINES: usize = 150;
/// New entries an oldest-first poll reads at least: 3200 a search (50 pages
/// of 64 on the fake) less an overlap of at most 120 s at 12 entries a
/// second.
const PER_POLL: usize = 1600;
/// For two polls and a minute after an engine starts (its first poll), an
/// address found already listed is not a bypass (README, "Bans that do not
/// block"); the simulation keeps the default `poll_interval` of 30 s.
const STARTUP_GRACE: i64 = 2 * 30 + 60;

const BASE_NETS: [&str; 4] = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
];
const OWNER_NET: &str = "203.0.113.16/29";
const PERSISTENT: [&str; 6] = [
    "198.51.100.1",
    "198.51.100.2",
    "198.51.100.3",
    "192.0.2.10",
    "192.0.2.11",
    "203.0.113.50",
];
const OCCASIONAL: [&str; 3] = ["198.51.100.20", "192.0.2.30", "203.0.113.60"];
const OWNERS: [&str; 3] = ["203.0.113.17", "203.0.113.18", "203.0.113.21"];
const PRIVATE: [&str; 4] = ["192.168.1.50", "10.0.0.7", "172.16.0.9", "127.0.0.1"];
const USERS: [&str; 4] = ["admin", "illegal usernam", "", "user1"];
/// The address the host reaches its devices from (`own::Fixed`): an own
/// address, which no other part of a scenario uses.
const OWN: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 200);
const OWN_TEXT: &str = "192.0.2.200";
/// The user name hik-f2b logs in with (`support/fake.rs`).
const OWN_USER: &str = "f2b";
/// The safe list of the scenarios that have one.
const SAFE: &str = "cctv_safe";
/// The request with which an engine start counts the entries of the
/// address-list (`start/count`).
const COUNT_REQUEST: &str = "GET /rest/ip/firewall/address-list?list=cctv_ban&.proplist=address";
/// The host name in `ignoreip` of the scenarios that have one, and the
/// addresses its answers give, which no other part of a scenario uses.
const NAME: &str = "home.example.net";
const NAMED: [&str; 2] = ["203.0.113.80", "203.0.113.81"];
/// The interval of the periodic firewall check (`health::HEALTH_CHECK_INTERVAL`).
const CHECK_EVERY: i64 = 300;
const FAIL: &str = "illlegealAccess";
const OTHER: &str = "videoLost/30";
const NOTICES: [(&str, &str); 4] = [
    ("ERROR health alert [", "alert"),
    ("ERROR health reminder [", "reminder"),
    ("INFO health recovered [", "recovered"),
    ("INFO health unknown [", "unknown"),
];

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        // splitmix64, so that neighbouring seeds differ from the start
        let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Rng((z ^ (z >> 31)) | 1)
    }

    fn step(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// `0 .. n`
    fn below(&mut self, n: u64) -> u64 {
        self.step() % n.max(1)
    }

    /// `lo ..= hi`
    fn range(&mut self, lo: i64, hi: i64) -> i64 {
        lo + self.below((hi - lo + 1) as u64) as i64
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len() as u64) as usize]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Firewall,
    Backlog,
    DryRun,
    NotifyOnly,
    Clock,
}

const CLASSES: [Class; 5] = [
    Class::Firewall,
    Class::Backlog,
    Class::DryRun,
    Class::NotifyOnly,
    Class::Clock,
];

struct Params {
    class: Class,
    nvrs: usize,
    maxretry: usize,
    findtime: i64,
    /// `None`: permanent.
    bantime: Option<i64>,
    lookback: i64,
    alert_after: i64,
    max_per_hour: usize,
    steps: usize,
}

impl Params {
    fn draw(class: Class, rng: &mut Rng) -> Params {
        let findtimes: &[i64] = if class == Class::Backlog {
            &[1800, 3600]
        } else {
            &[600, 1800, 3600]
        };
        let max_per_hour = rng.pick(&[3, 20, 1000]);
        let mut bantime = rng.pick(&[Some(14400), Some(86400), None]);
        if max_per_hour < 20 && bantime == Some(14400) {
            // bans waiting hours for the allowance must not expire meanwhile
            bantime = Some(86400);
        }
        Params {
            class,
            nvrs: 1 + rng.below(2) as usize,
            maxretry: rng.pick(&[3, 5, 5, 8]),
            findtime: rng.pick(findtimes),
            bantime,
            lookback: rng.pick(&[60, 120]),
            alert_after: rng.pick(&[60, 300, 600]),
            max_per_hour,
            steps: if class == Class::Backlog { 100 } else { 140 },
        }
    }

    /// How long a ban (or report) lasts for the engine.
    fn keep(&self) -> i64 {
        self.bantime.unwrap_or(86400)
    }

    /// No ban reaches the router: reports instead.
    fn report_once(&self) -> bool {
        matches!(self.class, Class::DryRun | Class::NotifyOnly)
    }

    fn general(&self, nets: &[String], name: bool) -> String {
        let bantime = match self.bantime {
            Some(s) => s.to_string(),
            None => "permanent".to_string(),
        };
        let dry = if self.class == Class::DryRun {
            "dry_run = true\n"
        } else {
            ""
        };
        format!(
            "maxretry = {}\nfindtime = {}\nbantime = {}\nlookback = {}\nalert_after = {}\n\
             max_bans_per_hour = {}\n{}{}",
            self.maxretry,
            self.findtime,
            bantime,
            self.lookback,
            self.alert_after,
            self.max_per_hour,
            dry,
            ignore_line(nets, name)
        )
    }

    fn describe(&self) -> String {
        let bantime = match self.bantime {
            Some(s) => s.to_string(),
            None => "permanent".to_string(),
        };
        format!(
            "nvrs={} maxretry={} findtime={} bantime={} lookback={} alert_after={} \
             max_bans_per_hour={}",
            self.nvrs,
            self.maxretry,
            self.findtime,
            bantime,
            self.lookback,
            self.alert_after,
            self.max_per_hour
        )
    }
}

/// The `ignoreip` line: the networks `nets` and, with `name`, `NAME`.
fn ignore_line(nets: &[String], name: bool) -> String {
    let mut items = nets.to_vec();
    if name {
        items.push(NAME.to_string());
    }
    format!("ignoreip = {}", items.join(", "))
}

/// An answer for `NAME`: one or both of `NAMED`, no IPv4 address, or a
/// failed look-up.
fn draw_answer(rng: &mut Rng) -> Result<Vec<Ipv4Addr>, String> {
    let a: Ipv4Addr = NAMED[0].parse().unwrap();
    let b: Ipv4Addr = NAMED[1].parse().unwrap();
    match rng.below(10) {
        0..=2 => Ok(vec![a]),
        3..=5 => Ok(vec![b]),
        6 => Ok(vec![b, a]),
        7 => Ok(vec![]),
        _ => Err(format!("cannot resolve {}: timed out", NAME)),
    }
}

/// The addresses of an answer that exempt something, sorted: none for one
/// that failed or found no IPv4 address.
fn found(answer: &Result<Vec<Ipv4Addr>, String>) -> Option<Vec<Ipv4Addr>> {
    let mut addresses = answer.as_ref().ok().filter(|a| !a.is_empty())?.clone();
    addresses.sort_unstable();
    Some(addresses)
}

/// `203.0.113.80 and 203.0.113.81`, or `none`, as hik-f2b lists them.
fn and_list(addresses: &[Ipv4Addr]) -> String {
    if addresses.is_empty() {
        return "none".to_string();
    }
    addresses
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(" and ")
}

fn in_net(ip: Ipv4Addr, net: &str) -> bool {
    let (addr, len) = net.split_once('/').unwrap_or((net, "32"));
    let addr: Ipv4Addr = addr.parse().unwrap();
    let len: u32 = len.parse().unwrap();
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    u32::from(ip) & mask == u32::from(addr) & mask
}

/// Never banned under `nets`, by the README's list, and the own address.
fn exempt(nets: &[String], ip: Ipv4Addr) -> bool {
    let first = ip.octets()[0];
    ip == OWN
        || ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_link_local()
        || first == 0
        || first >= 240
        || nets.iter().any(|net| in_net(ip, net))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Router {
    Ok,
    Unreachable,
    Refusing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Ok,
    Down,
    Garbage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ban {
    Accepted,
    Listed,
    Reported,
}

#[derive(Clone, Copy)]
enum Kind {
    Poll,
    Fail,
    Router,
    Nvr,
    Order,
    Restart,
    List,
    Flood,
    Clock,
    Own,
    OwnListed,
}

struct NvrSim {
    name: String,
    mode: Mode,
    skew: i64,
    /// Times the offset the engine stores for this NVR changed.
    offset_changes: usize,
    started: bool,
    last_flood: i64,
    /// Host times of its entries, in the order written (ascending).
    times: Vec<i64>,
}

/// What `count/shift` needs of a failed login logged after the start.
#[derive(Clone, Copy)]
struct Logged {
    /// True host time.
    host: i64,
    /// The offset the engine had stored for the NVR when it was logged.
    stored: Option<i64>,
    /// `NvrSim::offset_changes` when it was logged.
    changes: usize,
}

/// One generated log entry.
struct Gen {
    nvr: usize,
    /// True host time.
    host: i64,
    /// Its time in the log (device time).
    device: i64,
    /// The address it counts for, if it is a failed login with an IPv4
    /// (or IPv4-mapped) address.
    ip: Option<Ipv4Addr>,
    /// Logged after its NVR's first successful poll.
    after_start: bool,
    /// Cycles run before it was logged.
    seq: usize,
    /// In a stretch the engine reported as skipped.
    lost: bool,
}

struct Cycle {
    host: i64,
    instance: usize,
    nvr_ok: Vec<bool>,
    router: Router,
    pending_after: bool,
    /// A ban attempt found the firewall unreachable.
    transport: bool,
    /// A ban was refused (the address is not listed).
    refused: bool,
    /// A ban was applied or found already listed.
    ban_pass: bool,
    /// The router accepted a ban or listed it, or answered a check that
    /// ended the firewall problem.
    router_pass: bool,
    notices: Vec<String>,
}

/// The health policy of the README, fed with what the engine observed.
#[derive(Default)]
struct Health {
    /// key -> (since, last alert or reminder)
    open: BTreeMap<String, (i64, Option<i64>)>,
    closed: Vec<String>,
    /// The last ban attempt found the firewall unreachable, and no check
    /// failed since: the `firewall` problem is one that only writes show,
    /// which a check that works does not end.
    write_failed: bool,
}

impl Health {
    fn fail(&mut self, key: &str, now: i64) {
        self.open.entry(key.to_string()).or_insert((now, None));
    }

    fn close(&mut self, key: &str, kind: &str) {
        if let Some((_, Some(_))) = self.open.remove(key) {
            self.closed.push(format!("{} {}", kind, key));
        }
    }

    fn pass(&mut self, key: &str) {
        self.close(key, "recovered");
    }

    fn withdraw(&mut self, key: &str) {
        self.close(key, "unknown");
    }

    fn due(&mut self, now: i64, alert_after: i64) -> Vec<String> {
        let mut out = std::mem::take(&mut self.closed);
        for (key, (since, alerted)) in self.open.iter_mut() {
            let kind = match *alerted {
                None if now - *since >= alert_after => "alert",
                Some(last) if now - last >= 86400 => "reminder",
                _ => continue,
            };
            *alerted = Some(now);
            out.push(format!("{} {}", kind, key));
        }
        out
    }
}

/// What a log line of the engine says, as far as the checks care.
enum Line {
    Counted(usize, Ipv4Addr, i64),
    Ban(Ipv4Addr, Ban),
    /// Already listed, but still reached the NVR well after its ban.
    Bypass(Ipv4Addr),
    Transport(Ipv4Addr),
    Refused(Ipv4Addr),
    CheckFailed,
    Limited,
    Dropped(Ipv4Addr),
    Skipped(usize, i64, i64),
    SkippedAll(usize),
    Notice(String),
    /// A failed login said to come from an own address.
    OwnLogin(Ipv4Addr),
    /// An own address found in the address-list: removed, reported in a
    /// dry run, or not removed (refused).
    OwnRemoved(Ipv4Addr),
    OwnDryRun(Ipv4Addr),
    OwnStuck(Ipv4Addr),
    /// The look-up of an own address failed.
    OwnAskFailed,
    /// A line about a safe list: what a dry run would write, an address
    /// added, a write that failed, a rule check that passed or failed, or
    /// anything else that names it.
    SafeDry(Ipv4Addr),
    SafeAdded(Ipv4Addr),
    SafeWriteFailed(Ipv4Addr),
    SafeRuleOk,
    SafeRuleFailed,
    SafeOther,
    /// A failed login said to be exempt for this `ignoreip` name, and a
    /// waiting ban or counted failed logins dropped for one.
    NameExempt(Ipv4Addr, String),
    NameDropped(Ipv4Addr, String),
    /// Any other line about an `ignoreip` name.
    NameLog(String),
    /// The number of entries in an address-list, said at an engine start,
    /// and a count that failed.
    ListSize(String, usize),
    ListSizeFailed,
    Other,
}

fn nvr_index(name: &str) -> Option<usize> {
    name.strip_prefix("nvr")?
        .parse::<usize>()
        .ok()?
        .checked_sub(1)
}

fn address_after(text: &str, prefix: &str) -> Option<Ipv4Addr> {
    text.strip_prefix(prefix)?.split(' ').next()?.parse().ok()
}

/// `nvr1: failed login from 198.51.100.1 (user="admin") at <time> [3/5]`
fn counted(text: &str) -> Option<(usize, Ipv4Addr, i64)> {
    let (nvr, rest) = text.split_once(": failed login from ")?;
    if !rest.ends_with(']') {
        return None;
    }
    let (ip, _) = rest.split_once(' ')?;
    let at = rest.rfind(") at ")?;
    Some((
        nvr_index(nvr)?,
        ip.parse().ok()?,
        util::parse_ts(&rest[at..])?,
    ))
}

fn skipped(rest: &str, marker: &str) -> Option<(i64, i64)> {
    let range = &rest[rest.find(marker)? + marker.len()..];
    let from = util::parse_ts(range)?;
    let to = util::parse_ts(&range[range.find(" .. ")? + 4..])?;
    Some((from, to))
}

fn classify(line: &str) -> Line {
    for (prefix, kind) in NOTICES {
        if let Some(rest) = line.strip_prefix(prefix) {
            if let Some((key, _)) = rest.split_once(']') {
                return Line::Notice(format!("{} {}", kind, key));
            }
        }
    }
    let text = line.split_once(' ').map_or("", |(_, text)| text);
    if let Some((_, rest)) = text.split_once(": failed login from ") {
        if let Some((ip, rest)) = rest.split_once(' ') {
            if let Some((_, name)) = rest.split_once("): never banned (ignoreip name ") {
                if let (Ok(ip), Some((name, _))) = (ip.parse(), name.split_once(')')) {
                    return Line::NameExempt(ip, name.to_string());
                }
            }
        }
    }
    if let Some((_, name)) = text.split_once(": the address is now what the ignoreip name ") {
        if let (Some((ip, _)), Some((name, _))) = (text.split_once(':'), name.split_once(' ')) {
            if let Ok(ip) = ip.parse() {
                return Line::NameDropped(ip, name.to_string());
            }
        }
    }
    if text.starts_with("ignoreip") {
        return Line::NameLog(line.to_string());
    }
    if let Some(rest) = text.strip_prefix("MikroTik address-list ") {
        if let Some((list, n)) = rest.split_once(" has ") {
            if let Some(Ok(n)) = n.strip_suffix(" entries").map(str::parse) {
                return Line::ListSize(list.to_string(), n);
            }
        }
    }
    if text.starts_with("cannot count the entries of address-list ") {
        return Line::ListSizeFailed;
    }
    if let Some((n, ip, ts)) = counted(text) {
        return Line::Counted(n, ip, ts);
    }
    if let Some(ip) = address_after(text, "BAN ") {
        return Line::Ban(ip, Ban::Accepted);
    }
    if let Some(ip) = address_after(text, "DETECTED ") {
        return Line::Ban(ip, Ban::Reported);
    }
    if let Some(ip) = address_after(text, "DRY RUN: would ban ") {
        return Line::Ban(ip, Ban::Reported);
    }
    if let Some(ip) = address_after(text, "cannot remove own address ") {
        return Line::OwnStuck(ip);
    }
    if text.starts_with("cannot ask ") && text.contains(" whether own address ") {
        return Line::OwnAskFailed;
    }
    if let Some(ip) = address_after(text, "cannot write own address ") {
        return Line::SafeWriteFailed(ip);
    }
    if let Some(ip) = address_after(text, "DRY RUN: would keep ") {
        return Line::SafeDry(ip);
    }
    if text.starts_with("safe list check failed: ") {
        return Line::SafeRuleFailed;
    }
    if text.starts_with("safe list check ok: ") {
        return Line::SafeRuleOk;
    }
    if let Some((ip, rest)) = text.split_once(' ') {
        if rest.starts_with("added to the safe list ") {
            if let Ok(ip) = ip.parse() {
                return Line::SafeAdded(ip);
            }
        }
    }
    if text.contains("safe list") {
        return Line::SafeOther;
    }
    if let Some(rest) = text.strip_prefix("DRY RUN: ") {
        if let Some((ip, rest)) = rest.split_once(' ') {
            if rest.starts_with("is an own address of hik-f2b and is in ") {
                if let Ok(ip) = ip.parse() {
                    return Line::OwnDryRun(ip);
                }
            }
        }
    }
    if let Some((ip, rest)) = text.split_once(' ') {
        if rest.starts_with("is an own address of hik-f2b and was in ") {
            if let Ok(ip) = ip.parse() {
                return Line::OwnRemoved(ip);
            }
        }
    }
    if let Some((_, rest)) = text.split_once(": failed login from ") {
        if let Some((ip, rest)) = rest.split_once(' ') {
            if rest.contains("): an own address of hik-f2b, ") {
                if let Ok(ip) = ip.parse() {
                    return Line::OwnLogin(ip);
                }
            }
        }
    }
    if let Some(ip) = address_after(text, "cannot ban ") {
        if text.contains(", will retry next cycle: ") {
            return Line::Transport(ip);
        }
        return Line::Refused(ip);
    }
    if text.starts_with("firewall check failed") {
        return Line::CheckFailed;
    }
    if text.starts_with("ban rate limit reached") {
        return Line::Limited;
    }
    if let Some((first, rest)) = text.split_once(' ') {
        if let Ok(ip) = first.trim_end_matches(':').parse::<Ipv4Addr>() {
            if rest.starts_with("is already in ") {
                if rest.contains(" but still reached the NVR") {
                    return Line::Bypass(ip);
                }
                return Line::Ban(ip, Ban::Listed);
            }
            if rest.starts_with("the ban could not be applied") {
                return Line::Dropped(ip);
            }
        }
    }
    if let Some((nvr, rest)) = text.split_once(": ") {
        if let Some(n) = nvr_index(nvr) {
            for marker in ["SKIPPING the log window ", "not every log entry in "] {
                if let Some((from, to)) = skipped(rest, marker) {
                    return Line::Skipped(n, from, to);
                }
            }
            if rest.contains("more log entries within one second") {
                return Line::SkippedAll(n);
            }
        }
    }
    Line::Other
}

/// Whether a notification is the one sent at once about the own address
/// in the address-list.
fn own_notice(body: &str) -> bool {
    fake::text_of(body).starts_with(&format!(
        "\u{26a0}\u{fe0f} hik-f2b: {} is an own address of hik-f2b and ",
        OWN_TEXT
    ))
}

/// The address a ban notification is about.
fn ban_notice(body: &str) -> Option<Ipv4Addr> {
    let text = fake::text_of(body);
    let rest = text.strip_prefix("\u{26d4} hik-f2b: ")?;
    rest.split(' ').next()?.parse().ok()
}

/// What a firewall check did about the safe list, from the lines of one
/// cycle (or engine start).
#[derive(Default)]
struct SafeSeen {
    dry: usize,
    added: usize,
    failed: usize,
    rule_failed: usize,
    other: usize,
}

impl SafeSeen {
    /// Takes one classified line; `safe/only` for one about another address
    /// than `OWN`.
    fn see(&mut self, line: &Line) -> Result<(), String> {
        let ip = match line {
            Line::SafeDry(ip) => {
                self.dry += 1;
                ip
            }
            Line::SafeAdded(ip) => {
                self.added += 1;
                ip
            }
            Line::SafeWriteFailed(ip) => {
                self.failed += 1;
                ip
            }
            Line::SafeRuleOk => return Ok(()),
            Line::SafeRuleFailed => {
                self.rule_failed += 1;
                return Ok(());
            }
            Line::SafeOther => {
                self.other += 1;
                return Ok(());
            }
            _ => return Ok(()),
        };
        if *ip != OWN {
            return Err(format!("[safe/only] a line about {} in the safe list", ip));
        }
        Ok(())
    }

    fn any(&self) -> bool {
        self.dry + self.added + self.failed + self.rule_failed + self.other > 0
    }
}

/// The safe list of a scenario that has one.
struct SafeSim {
    /// The accept rule is there, above the drop rule.
    rule: bool,
    /// When the fake router expires the entry of `OWN`.
    until: Option<i64>,
    /// The engine running now has said what a dry run would write.
    dry_said: bool,
    /// Writes the router accepted.
    writes: usize,
}

/// The host name in `ignoreip` of a scenario that has one.
struct NameSim {
    /// What the fixed answer for `NAME` gives now.
    answer: Result<Vec<Ipv4Addr>, String>,
    /// What the name resolves to for the engine running now: the answer of
    /// its last look-up that found an address (empty if none did).
    known: Vec<Ipv4Addr>,
    /// The last look-up of the engine running now failed.
    failing: bool,
    /// Look-ups that reached the fixed answers so far.
    resolved: usize,
    /// The host time from which the next look-up is counted; `None` before
    /// the first poll of the engine running now.
    since: Option<i64>,
    /// The addresses the name resolved to at some time.
    ever: Vec<Ipv4Addr>,
    /// For the summary: look-ups, and the ones that changed `known`.
    lookups: usize,
    changes: usize,
}

impl NameSim {
    /// The look-up of a new engine. Returns the lines its start must log
    /// (`name/log`), each a prefix.
    fn started(&mut self) -> Vec<String> {
        self.lookups += 1;
        self.since = None;
        let found = found(&self.answer);
        self.failing = found.is_none();
        self.known = found.unwrap_or_default();
        self.remember();
        let mut lines = vec![format!(
            "INFO ignoreip names, never banned: {} {}",
            NAME,
            if self.known.is_empty() {
                "not resolved".to_string()
            } else {
                and_list(&self.known)
            }
        )];
        if self.failing {
            lines.push(format!(
                "WARNING ignoreip: {} does not resolve, so it exempts no address until it does; \
                 it is tried again every 5 min: ",
                NAME
            ));
        }
        lines
    }

    /// A look-up in a poll. Returns the lines it must log, each a prefix.
    fn looked_up(&mut self) -> Vec<String> {
        self.lookups += 1;
        let before = self.known.clone();
        let was_failing = self.failing;
        let found = found(&self.answer);
        self.failing = found.is_none();
        if let Some(found) = found {
            self.known = found;
        }
        self.remember();
        if self.known != before {
            self.changes += 1;
            return vec![format!(
                "INFO ignoreip: {} now resolves to {} (was {})",
                NAME,
                and_list(&self.known),
                and_list(&before)
            )];
        }
        match (was_failing, self.failing) {
            (false, true) => vec![format!(
                "WARNING ignoreip: the look-up of {} failed, the addresses it last resolved to \
                 stay exempt ({}): ",
                NAME,
                and_list(&self.known)
            )],
            (true, false) => vec![format!(
                "INFO ignoreip: the look-up of {} works again, it still resolves to {}",
                NAME,
                and_list(&self.known)
            )],
            _ => vec![],
        }
    }

    fn remember(&mut self) {
        for ip in &self.known {
            if !self.ever.contains(ip) {
                self.ever.push(*ip);
            }
        }
    }
}

/// The lines of one cycle (or engine start) about own addresses.
#[derive(Default)]
struct OwnSeen {
    logins: usize,
    removed: usize,
    dry_run: usize,
    stuck: usize,
    ask_failed: bool,
    /// Entries the router removed.
    deleted: usize,
}

impl OwnSeen {
    /// Takes the requests to remove an entry that reached the router;
    /// `own/only` for one that is not about `OWN`.
    fn deletes(&mut self, router: &Mutex<Fake>) -> Result<(), String> {
        let deletes = std::mem::take(&mut router.lock().unwrap().delete_log);
        for (address, outcome) in deletes {
            if address != OWN_TEXT {
                return Err(format!(
                    "[own/only] a request to remove the entry of {:?} ({})",
                    address, outcome
                ));
            }
            if outcome == "removed" {
                self.deleted += 1;
            }
        }
        Ok(())
    }

    /// Takes one classified line; `own/other` for an own address that is
    /// not `OWN`.
    fn see(&mut self, line: &Line) -> Result<(), String> {
        let ip = match line {
            Line::OwnLogin(ip) => {
                self.logins += 1;
                ip
            }
            Line::OwnRemoved(ip) => {
                self.removed += 1;
                ip
            }
            Line::OwnDryRun(ip) => {
                self.dry_run += 1;
                ip
            }
            Line::OwnStuck(ip) => {
                self.stuck += 1;
                ip
            }
            Line::OwnAskFailed => {
                self.ask_failed = true;
                return Ok(());
            }
            _ => return Ok(()),
        };
        if *ip != OWN {
            return Err(format!(
                "[own/other] {} is said to be an own address of hik-f2b",
                ip
            ));
        }
        Ok(())
    }
}

struct Sim {
    seed: u64,
    rng: Rng,
    p: Params,
    h: Harness,
    t0: i64,
    host: i64,
    nets: Vec<String>,
    configs: Vec<Vec<String>>,
    instance: usize,
    nvr: Vec<NvrSim>,
    router: Router,
    /// Timed bans in the fake router and when it expires them.
    expiry: Vec<(String, i64)>,
    gens: Vec<Gen>,
    by_ip: HashMap<Ipv4Addr, Vec<usize>>,
    unsorted: bool,
    cycles: Vec<Cycle>,
    /// The failed logins logged after the start, by (nvr, address, device
    /// time).
    generated: HashMap<(usize, Ipv4Addr, i64), Vec<Logged>>,
    /// Failed logins counted, by (nvr, address, device time).
    counted: HashMap<(usize, Ipv4Addr, i64), u32>,
    /// Per address, the largest shift of a counted failed login: the host
    /// time the engine counted it at minus its true host time (see
    /// `safety/maxretry` in the module comment).
    shift: HashMap<Ipv4Addr, i64>,
    bans: Vec<(i64, Ipv4Addr, Ban)>,
    dropped: HashSet<Ipv4Addr>,
    health: Health,
    /// When a listed address last reached an NVR well after its ban (see
    /// `health/model`).
    last_bypass: Option<i64>,
    /// Host time of the first poll of the engine running now.
    started_at: Option<i64>,
    /// Addresses the liveness check had a due ban or report for.
    musts: usize,
    /// `OWN` stays listed after a check that answered, and that was
    /// reported (`own/notify`); the engine running now knows it.
    own_reported: bool,
    /// Notifications about `OWN` in the address-list that the engine
    /// running now still has to send.
    own_notices: usize,
    /// Removals of `OWN` and reports of it in a dry run.
    own_removed: usize,
    own_kept: usize,
    /// The safe list, if the scenario has one.
    safe: Option<SafeSim>,
    /// The host name in `ignoreip`, if the scenario has one, and the
    /// generator of its events.
    name: Option<NameSim>,
    name_rng: Rng,
    trace: Vec<String>,
}

impl Sim {
    fn new(seed: u64) -> Sim {
        let class = CLASSES[(seed % CLASSES.len() as u64) as usize];
        let mut rng = Rng::new(seed);
        let p = Params::draw(class, &mut rng);
        let mut nets: Vec<String> = BASE_NETS.iter().map(|n| n.to_string()).collect();
        if rng.chance(50) {
            nets.push(OWNER_NET.to_string());
        }
        // Drawn apart from the scenario: the same seed gives the same other
        // events with and without the name.
        let mut name_rng = Rng::new(seed ^ 0x4e41_4d45_4e41_4d45);
        let name = name_rng.chance(50).then(|| NameSim {
            answer: draw_answer(&mut name_rng),
            known: Vec::new(),
            failing: false,
            resolved: 0,
            since: None,
            ever: Vec::new(),
            lookups: 0,
            changes: 0,
        });
        let general: &'static str = Box::leak(p.general(&nets, name.is_some()).into_boxed_str());
        // The answer the first engine gets; a failed look-up is the fixed
        // answers' own for a name they do not know.
        let names: &'static [(&'static str, &'static [&'static str])] =
            match name.as_ref().map(|n| &n.answer) {
                Some(Ok(addresses)) => {
                    let texts: Vec<&'static str> = addresses
                        .iter()
                        .map(|ip| -> &'static str { Box::leak(ip.to_string().into_boxed_str()) })
                        .collect();
                    let texts: &'static [&'static str] = Box::leak(texts.into_boxed_slice());
                    Box::leak(vec![(NAME, texts)].into_boxed_slice())
                }
                _ => &[],
            };
        // Drawn apart from the scenario: the same seed gives the same events
        // with and without a safe list.
        let mut own_rng = Rng::new(seed ^ 0x5afe_5afe_5afe_5afe);
        let safe = (class != Class::NotifyOnly && own_rng.chance(50)).then(|| SafeSim {
            rule: own_rng.chance(80),
            until: None,
            dry_said: false,
            writes: 0,
        });
        let h = Harness::build(Opts {
            telegram: true,
            mikrotik: class != Class::NotifyOnly,
            second_nvr: p.nvrs == 2,
            general,
            mikrotik_extra: if safe.is_some() {
                "safe_list = cctv_safe"
            } else {
                ""
            },
            own: OWN,
            names,
            ..Default::default()
        });
        if let Some(Err(e)) = name.as_ref().map(|n| &n.answer) {
            h.own.set_name(NAME, Err(e.clone()));
        }
        if safe.as_ref().is_some_and(|s| s.rule) {
            h.fake.lock().unwrap().rules = vec![
                fake::Rule::accept("raw", SAFE),
                fake::Rule::new("raw", "cctv_ban", false),
            ];
        }
        let nvr = (0..p.nvrs)
            .map(|n| NvrSim {
                name: format!("nvr{}", n + 1),
                mode: Mode::Ok,
                skew: SKEW,
                offset_changes: 0,
                started: false,
                last_flood: i64::MIN / 2,
                times: Vec::new(),
            })
            .collect();
        Sim {
            seed,
            rng,
            p,
            t0: h.host,
            host: h.host,
            h,
            configs: vec![nets.clone()],
            nets,
            instance: 0,
            nvr,
            router: Router::Ok,
            expiry: Vec::new(),
            gens: Vec::new(),
            by_ip: HashMap::new(),
            unsorted: false,
            cycles: Vec::new(),
            generated: HashMap::new(),
            counted: HashMap::new(),
            shift: HashMap::new(),
            bans: Vec::new(),
            dropped: HashSet::new(),
            health: Health::default(),
            last_bypass: None,
            started_at: None,
            musts: 0,
            own_reported: false,
            own_notices: 0,
            own_removed: 0,
            own_kept: 0,
            safe,
            name,
            name_rng,
            trace: Vec::new(),
        }
    }

    fn note(&mut self, text: String) {
        let line = format!("{:>7}s {}", self.host - self.t0, text);
        self.trace.push(line);
    }

    fn fake(&self, n: usize) -> Arc<Mutex<Fake>> {
        if n == 0 {
            Arc::clone(&self.h.fake)
        } else {
            Arc::clone(self.h.fake2.as_ref().unwrap())
        }
    }

    fn listed(&self, address: &str) -> bool {
        self.h
            .fake
            .lock()
            .unwrap()
            .bans
            .iter()
            .any(|b| b == address)
    }

    /// Writes one entry into NVR `n`'s log at host time `host`. `counts`:
    /// the IPv4 address of a failed login, if it has one.
    fn write(&mut self, n: usize, host: i64, address: &str, minor: &str, counts: Option<Ipv4Addr>) {
        let user = self.rng.pick(&USERS);
        self.write_as(n, host, address, minor, counts, user);
    }

    /// `write` with the user name `user`.
    fn write_as(
        &mut self,
        n: usize,
        host: i64,
        address: &str,
        minor: &str,
        counts: Option<Ipv4Addr>,
        user: &str,
    ) {
        let device = host + self.nvr[n].skew;
        let entry = Entry {
            ts: fake::device(device),
            minor: minor.to_string(),
            ip: address.to_string(),
            user: user.as_bytes().to_vec(),
        };
        self.fake(n).lock().unwrap().entries.push(entry);
        self.unsorted = true;
        let ip = if minor == FAIL { counts } else { None };
        let after_start = self.nvr[n].started;
        let index = self.gens.len();
        self.gens.push(Gen {
            nvr: n,
            host,
            device,
            ip,
            after_start,
            seq: self.cycles.len(),
            lost: false,
        });
        self.nvr[n].times.push(host);
        if let Some(ip) = ip {
            self.by_ip.entry(ip).or_default().push(index);
            if after_start {
                let stored = self
                    .h
                    .engine
                    .state()
                    .cursors
                    .get(&self.nvr[n].name)
                    .and_then(|st| st.offset());
                let logged = Logged {
                    host,
                    stored,
                    changes: self.nvr[n].offset_changes,
                };
                self.generated
                    .entry((n, ip, device))
                    .or_default()
                    .push(logged);
            }
        }
    }

    fn run(&mut self) -> Result<(), String> {
        self.start()?;
        for _ in 0..self.p.steps {
            self.step()?;
        }
        self.settle()?;
        if matches!(self.p.class, Class::Firewall | Class::Backlog) {
            self.check_stretches("firewall", Router::Unreachable)?;
            self.check_stretches("ban-refused", Router::Refusing)?;
        }
        if self.p.class != Class::Clock {
            self.musts = self.check_liveness()?;
        }
        Ok(())
    }

    fn start(&mut self) -> Result<(), String> {
        let text = format!("class {:?}: {}", self.p.class, self.p.describe());
        self.note(text);
        let text = ignore_line(&self.nets, self.name.is_some());
        self.note(text);
        if let Some(n) = &self.name {
            let text = format!("{} answers {:?}", NAME, n.answer);
            self.note(text);
        }
        if let Some(s) = &self.safe {
            let text = format!(
                "safe list {}, {}",
                SAFE,
                if s.rule {
                    "accept rule above the drop rule"
                } else {
                    "no accept rule"
                }
            );
            self.note(text);
        }
        for n in 0..self.p.nvrs {
            let percent = if self.p.class == Class::Backlog {
                60
            } else {
                25
            };
            if self.rng.chance(percent) {
                self.fake(n).lock().unwrap().newest_first = true;
                let text = format!("{} lists newest first", self.nvr[n].name);
                self.note(text);
            }
            if self.rng.chance(15) {
                self.set_nvr(n, Mode::Down);
            }
        }
        // failed logins already in the logs at the first start
        let mut backlog: Vec<(i64, usize, &str)> = Vec::new();
        for _ in 0..self.rng.range(1, 4) {
            let address = if self.rng.chance(70) {
                self.rng.pick(&PERSISTENT)
            } else {
                self.rng.pick(&OWNERS)
            };
            let n = self.rng.below(self.p.nvrs as u64) as usize;
            let first = self.rng.range(1, 300);
            let count = self.rng.range(1, self.p.maxretry as i64 + 2);
            for i in 0..count {
                let t = self.host - first + 5 * i;
                if t < self.host {
                    backlog.push((t, n, address));
                }
            }
            let text = format!(
                "before the start: {} x{} from -{}s on {}",
                address, count, first, self.nvr[n].name
            );
            self.note(text);
        }
        backlog.sort();
        for (t, n, address) in backlog {
            self.write(n, t, address, FAIL, address.parse().ok());
        }
        let expected = self.name_lookups(true)?;
        // What the fakes hold before the start. Its first steps (the own
        // addresses, the `ignoreip` names, the country database, which the
        // harness does not configure) only log, so this is also what its
        // firewall check finds.
        let listed = self.listed(OWN_TEXT);
        let named = self.named_listed();
        self.expire_safe();
        let safe_before = self.safe_listed();
        // as `main.rs` starts the service
        self.h.engine.start(self.host as u64);
        self.named_kept(&named, "at the engine start")?;
        self.startup_lines(listed, safe_before, &expected)?;
        self.note("first poll".to_string());
        self.cycle()
    }

    /// The log of an engine start: what the name resolves to (`expected`,
    /// see `name_lookups`), the firewall check, and the look-up of the own
    /// address and the count of the address-list that follow it when the
    /// router answers.
    fn startup_lines(
        &mut self,
        listed_before: bool,
        safe_before: bool,
        expected: &[String],
    ) -> Result<(), String> {
        let lines = util::captured_log();
        let mut own = OwnSeen::default();
        let mut safe = SafeSeen::default();
        let mut about_name = Vec::new();
        let mut sizes = Vec::new();
        own.deletes(&self.h.fake)?;
        for line in &lines {
            let line = classify(line);
            safe.see(&line)?;
            match line {
                Line::ListSize(list, n) => sizes.push(Some((list, n))),
                Line::ListSizeFailed => sizes.push(None),
                Line::NameExempt(ip, name) => {
                    self.named_line(ip, &name, "a failed login said to be exempt")?
                }
                Line::NameDropped(ip, name) => self.named_line(ip, &name, "a drop")?,
                Line::NameLog(text) => about_name.push(text),
                Line::CheckFailed => {
                    if self.router != Router::Unreachable {
                        return Err(format!(
                            "[health/condition] the firewall check failed at startup while the \
                             router was {:?}",
                            self.router
                        ));
                    }
                    self.health.fail("firewall", self.host);
                }
                other => own.see(&other)?,
            }
        }
        self.name_logged(&about_name, expected)?;
        let answered = self.p.class != Class::NotifyOnly && self.router != Router::Unreachable;
        self.count_checked(answered, &sizes)?;
        self.safe_checked(answered, safe_before, &safe)?;
        self.own_swept(answered, listed_before, &own)
    }

    /// See `start/count` in the module comment: the counts of the
    /// address-list said since the last call (`said`: list and number, or
    /// `None` for a count that failed) and the requests the fake router
    /// recorded since then (before `safe_checked` takes them). `answered`:
    /// at an engine start whose firewall check the router answered; false
    /// in a cycle.
    fn count_checked(
        &self,
        answered: bool,
        said: &[Option<(String, usize)>],
    ) -> Result<(), String> {
        let f = self.h.fake.lock().unwrap();
        let asked: Vec<usize> = (0..f.rest_log.len())
            .filter(|&i| f.rest_log[i] == COUNT_REQUEST)
            .collect();
        if !answered {
            if !said.is_empty() || !asked.is_empty() {
                return Err(format!(
                    "[start/count] {:?} said and {} count request(s) outside an engine start \
                     whose firewall check the router answered",
                    said,
                    asked.len()
                ));
            }
            return Ok(());
        }
        if asked != [f.rest_log.len() - 1] {
            return Err(format!(
                "[start/count] the count request is not once and last at an engine start: {:?}",
                f.rest_log
            ));
        }
        let wanted = [Some(("cctv_ban".to_string(), f.bans.len()))];
        if said != wanted.as_slice() {
            return Err(format!(
                "[start/count] an engine start said {:?}, the address-list holds {} entries",
                said,
                f.bans.len()
            ));
        }
        Ok(())
    }

    /// Whether the safe list has an entry for `OWN`.
    fn safe_listed(&self) -> bool {
        let f = self.h.fake.lock().unwrap();
        f.listed.iter().any(|e| e.address == OWN_TEXT)
    }

    /// Removes the entry of `OWN` from the safe list once its timeout has
    /// passed, as the router does.
    fn expire_safe(&mut self) {
        let now = self.host;
        if let Some(s) = &mut self.safe {
            if s.until.is_some_and(|until| until <= now) {
                s.until = None;
                self.h
                    .fake
                    .lock()
                    .unwrap()
                    .listed
                    .retain(|e| e.list != SAFE);
            }
        }
    }

    /// See `safe/only`, `safe/off`, `safe/dry` and `safe/kept` in the module
    /// comment: what a firewall check (`answered`: the router answered it),
    /// or a cycle without one, must have done about the safe list, which
    /// held an entry for `OWN` before it or not (`had`), given the lines
    /// `seen` of the engine.
    fn safe_checked(&mut self, answered: bool, had: bool, seen: &SafeSeen) -> Result<(), String> {
        let (writes, listed, requests) = {
            let mut f = self.h.fake.lock().unwrap();
            (
                std::mem::take(&mut f.safe_log),
                f.listed.clone(),
                std::mem::take(&mut f.rest_log),
            )
        };
        for (list, address, outcome) in &writes {
            if list != SAFE || address != OWN_TEXT {
                return Err(format!(
                    "[safe/only] a write of {} to {} ({})",
                    address, list, outcome
                ));
            }
        }
        for entry in &listed {
            if entry.list != SAFE || entry.address != OWN_TEXT {
                return Err(format!(
                    "[safe/only] {} holds {}",
                    entry.list, entry.address
                ));
            }
        }
        let dry = self.p.class == Class::DryRun;
        let router = self.router;
        let host = self.host;
        let Some(s) = &mut self.safe else {
            if !writes.is_empty() || !listed.is_empty() || seen.any() {
                return Err(format!(
                    "[safe/off] without a safe list: writes {:?}, entries {:?}, {} line(s)",
                    writes,
                    listed,
                    seen.dry + seen.added + seen.failed + seen.rule_failed + seen.other
                ));
            }
            for request in &requests {
                let rules = request.contains("/rest/ip/firewall/raw")
                    || request.contains("/rest/ip/firewall/filter");
                if request.starts_with("PATCH")
                    || request.contains(SAFE)
                    || (rules && !request.contains("src-address-list=cctv_ban"))
                {
                    return Err(format!(
                        "[safe/off] a request without a safe list: {}",
                        request
                    ));
                }
            }
            return Ok(());
        };
        if seen.other > 0 {
            return Err(format!(
                "[safe/kept] {} line(s) about the safe list that say nothing known",
                seen.other
            ));
        }
        let rule_failed = usize::from(answered && !s.rule);
        if seen.rule_failed != rule_failed {
            return Err(format!(
                "[safe/kept] {} failed rule check(s) logged, expected {} (answered {}, rule {})",
                seen.rule_failed, rule_failed, answered, s.rule
            ));
        }
        if answered {
            if s.rule {
                self.health.pass("safe-list-rule");
            } else {
                self.health.fail("safe-list-rule", host);
            }
        }
        if dry {
            let said = usize::from(answered && !s.dry_said);
            if !writes.is_empty() || seen.dry != said || seen.failed > 0 {
                return Err(format!(
                    "[safe/dry] writes {:?}, {} line(s) of what it would write, expected {} \
                     (answered {})",
                    writes, seen.dry, said, answered
                ));
            }
            s.dry_said |= answered;
            return Ok(());
        }
        let expected: Vec<&str> = match (answered, router) {
            (false, _) => vec![],
            (true, Router::Refusing) => vec!["refused"],
            (true, _) if had => vec!["renewed"],
            (true, _) => vec!["added"],
        };
        let outcomes: Vec<&str> = writes.iter().map(|(_, _, o)| *o).collect();
        let lines = (seen.added, seen.failed);
        let expected_lines = (
            usize::from(expected == ["added"]),
            usize::from(expected == ["refused"]),
        );
        if outcomes != expected || lines != expected_lines {
            return Err(format!(
                "[safe/kept] writes {:?}, expected {:?}; (added, failed) lines {:?}, expected \
                 {:?} (answered {}, router {:?}, listed before {})",
                outcomes, expected, lines, expected_lines, answered, router, had
            ));
        }
        if !answered || router == Router::Refusing {
            if answered {
                self.health.fail("safe-list-refused", host);
            }
            return Ok(());
        }
        self.health.pass("safe-list-refused");
        s.writes += 1;
        let entries: Vec<_> = listed.iter().filter(|e| e.address == OWN_TEXT).collect();
        let timeout = match entries.as_slice() {
            [entry] => entry.timeout.as_deref().and_then(seconds),
            _ => None,
        };
        match timeout {
            Some(t) if t >= 3 * CHECK_EVERY => {
                s.until = Some(host + t);
                Ok(())
            }
            _ => Err(format!(
                "[safe/kept] after the check, {} holds {:?} for {}",
                SAFE, entries, OWN_TEXT
            )),
        }
    }

    /// See `own/removed`, `own/kept` and `own/notify` in the module comment:
    /// what a firewall check (`answered`: the router answered it) must have
    /// done about `OWN`, listed before it or not, given the lines `own` of
    /// the engine.
    fn own_swept(
        &mut self,
        answered: bool,
        listed_before: bool,
        own: &OwnSeen,
    ) -> Result<(), String> {
        let listed = self.listed(OWN_TEXT);
        let dry = self.p.class == Class::DryRun;
        let found = answered && listed_before;
        let (removed, stuck) = match (found, dry, self.router) {
            (false, _, _) => (0, 0),
            (true, true, _) => (0, 0),
            (true, false, Router::Refusing) => (0, 1),
            (true, false, _) => (1, 0),
        };
        let reported = usize::from(found && dry && !self.own_reported);
        let expected = (removed, reported, stuck);
        let seen = (own.removed, own.dry_run, own.stuck);
        if seen != expected {
            return Err(format!(
                "[own/removed] (removed, reported in a dry run, not removed) lines {:?}, \
                 expected {:?} (check answered {}, listed before {}, router {:?})",
                seen, expected, answered, listed_before, self.router
            ));
        }
        if listed != (listed_before && removed == 0) {
            return Err(format!(
                "[own/removed] {} is {}listed after a check (answered {}, listed before {}, \
                 router {:?})",
                OWN_TEXT,
                if listed { "" } else { "not " },
                answered,
                listed_before,
                self.router
            ));
        }
        if own.ask_failed {
            return Err("[own/removed] the look-up of the own address failed".to_string());
        }
        if own.deleted != own.removed {
            return Err(format!(
                "[own/only] the router removed {} entr(ies), {} removal(s) logged",
                own.deleted, own.removed
            ));
        }
        if removed > 0 {
            self.own_notices += 1;
            self.own_removed += 1;
            self.own_reported = false;
            self.note(format!("  -> {} removed from the address-list", OWN_TEXT));
        } else if found {
            if !self.own_reported {
                self.own_notices += 1;
                self.own_reported = true;
            }
            if dry {
                self.own_kept += reported;
            }
        } else if answered {
            self.own_reported = false;
        }
        if answered {
            if stuck > 0 {
                self.health.fail("own-address-listed", self.host);
            } else {
                self.health.pass("own-address-listed");
            }
        }
        Ok(())
    }

    fn step(&mut self) -> Result<(), String> {
        if self.name.is_some() && self.name_rng.chance(10) {
            self.name_event();
        }
        let class = self.p.class;
        let mut table = vec![
            (45, Kind::Poll),
            (33, Kind::Fail),
            (4, Kind::Nvr),
            (2, Kind::Order),
            (3, Kind::Restart),
        ];
        if class != Class::NotifyOnly {
            table.push((6, Kind::Router));
        }
        if !self.p.report_once() {
            table.push((2, Kind::List));
        }
        if class == Class::Backlog {
            table.push((5, Kind::Flood));
        }
        if class == Class::Clock {
            table.push((10, Kind::Clock));
        }
        table.push((3, Kind::Own));
        if class != Class::NotifyOnly {
            table.push((2, Kind::OwnListed));
        }
        let total: u64 = table.iter().map(|(weight, _)| weight).sum();
        let mut roll = self.rng.below(total);
        let mut kind = Kind::Poll;
        for (weight, k) in table {
            if roll < weight {
                kind = k;
                break;
            }
            roll -= weight;
        }
        match kind {
            Kind::Poll => {
                let r = self.rng.below(100);
                let dt = if r < 60 {
                    30
                } else if r < 85 {
                    self.rng.range(5, 60)
                } else if r < 95 {
                    self.rng.range(61, 300)
                } else {
                    self.rng.range(301, 900)
                };
                self.host += dt;
                self.note(format!("poll after {}s", dt));
                self.cycle()
            }
            Kind::Fail => {
                self.fail();
                Ok(())
            }
            Kind::Router => {
                let mode = if self.router != Router::Ok {
                    Router::Ok
                } else if self.rng.chance(50) {
                    Router::Unreachable
                } else {
                    Router::Refusing
                };
                self.set_router(mode);
                Ok(())
            }
            Kind::Nvr => {
                let n = self.rng.below(self.p.nvrs as u64) as usize;
                let mode = if self.nvr[n].mode != Mode::Ok {
                    Mode::Ok
                } else if self.rng.chance(50) {
                    Mode::Down
                } else {
                    Mode::Garbage
                };
                self.set_nvr(n, mode);
                Ok(())
            }
            Kind::Order => {
                let n = self.rng.below(self.p.nvrs as u64) as usize;
                let fake = self.fake(n);
                let newest = {
                    let mut f = fake.lock().unwrap();
                    f.newest_first = !f.newest_first;
                    f.newest_first
                };
                let order = if newest { "newest" } else { "oldest" };
                let text = format!("{} lists {} first", self.nvr[n].name, order);
                self.note(text);
                Ok(())
            }
            Kind::Restart => self.restart(),
            Kind::List => {
                let address = self.rng.pick(&PERSISTENT);
                if !self.listed(address) {
                    self.h.fake.lock().unwrap().bans.push(address.to_string());
                }
                self.note(format!("router: {} listed by hand", address));
                Ok(())
            }
            Kind::Flood => self.flood(),
            Kind::Clock => self.clock(),
            Kind::Own => {
                self.own_fail();
                Ok(())
            }
            Kind::OwnListed => {
                if !self.listed(OWN_TEXT) {
                    self.h.fake.lock().unwrap().bans.push(OWN_TEXT.to_string());
                }
                self.note(format!("router: {} listed by an outside hand", OWN_TEXT));
                Ok(())
            }
        }
    }

    /// Failed logins from the own address: with hik-f2b's user name, as
    /// while the NVR rejects hik-f2b's login, or with another, as a forged
    /// entry has. Enough to reach `maxretry` if they were counted.
    fn own_fail(&mut self) {
        let n = self.rng.below(self.p.nvrs as u64) as usize;
        let count = self.rng.range(1, self.p.maxretry as i64 + 3);
        let gap = self.rng.range(1, 30);
        let user = if self.rng.chance(50) {
            OWN_USER
        } else {
            self.rng.pick(&USERS)
        };
        for i in 0..count {
            self.write_as(n, self.host + i * gap, OWN_TEXT, FAIL, Some(OWN), user);
        }
        self.host += (count - 1) * gap;
        let text = format!(
            "fail {} {:?} (own) user {:?} x{} every {}s",
            self.nvr[n].name, OWN_TEXT, user, count, gap
        );
        self.note(text);
    }

    fn set_router(&mut self, mode: Router) {
        self.router = mode;
        {
            let mut f = self.h.fake.lock().unwrap();
            f.router_unreachable = mode == Router::Unreachable;
            f.refuse_writes = mode == Router::Refusing;
        }
        self.note(format!("router {:?}", mode));
    }

    fn set_nvr(&mut self, n: usize, mode: Mode) {
        self.nvr[n].mode = mode;
        {
            let fake = self.fake(n);
            let mut f = fake.lock().unwrap();
            f.nvr_down = mode == Mode::Down;
            f.garbage = mode == Mode::Garbage;
        }
        let text = format!("{} {:?}", self.nvr[n].name, mode);
        self.note(text);
    }

    /// Failed logins (and odd entries) from one address.
    fn fail(&mut self) {
        let n = self.rng.below(self.p.nvrs as u64) as usize;
        let m = self.p.maxretry as i64;
        let r = self.rng.below(100);
        let (pool, count, gap) = match r {
            0..=39 => (
                &PERSISTENT[..],
                self.rng.range(1, m + 3),
                self.rng.range(1, 20),
            ),
            40..=54 => (&OCCASIONAL[..], 1, 0),
            55..=71 => (&OWNERS[..], self.rng.range(1, m + 1), self.rng.range(2, 40)),
            72..=81 => (
                &PRIVATE[..],
                self.rng.range(1, m + 2),
                self.rng.range(1, 10),
            ),
            _ => (&PERSISTENT[..], self.rng.range(1, m), self.rng.range(1, 10)),
        };
        let plain = self.rng.pick(pool);
        let ip: Ipv4Addr = plain.parse().unwrap();
        let (address, minor, counts) = if r < 82 {
            (plain.to_string(), FAIL, Some(ip))
        } else {
            match self.rng.below(6) {
                0 => (format!("::ffff:{}", plain), FAIL, Some(ip)),
                1 => ("2001:db8::7".to_string(), FAIL, None),
                2 => (String::new(), FAIL, None),
                3 => ("0.0.0.0".to_string(), FAIL, None),
                4 => ("not-an-address".to_string(), FAIL, None),
                _ => (plain.to_string(), OTHER, None),
            }
        };
        // the drop rule keeps a listed address away from the NVR, mostly
        if !self.p.report_once() && counts.is_some() && self.listed(plain) && self.rng.chance(85) {
            self.note(format!("{} blocked by the router", plain));
            return;
        }
        for i in 0..count {
            self.write(n, self.host + i * gap, &address, minor, counts);
        }
        self.host += (count - 1) * gap;
        let text = format!(
            "fail {} {:?} {} x{} every {}s",
            self.nvr[n].name, address, minor, count, gap
        );
        self.note(text);
    }

    fn restart(&mut self) -> Result<(), String> {
        let old = ignore_line(&self.nets, self.name.is_some());
        let mut what = "same config".to_string();
        if self.rng.chance(60) {
            let net = if self.rng.chance(50) {
                OWNER_NET.to_string()
            } else {
                format!("{}/32", self.rng.pick(&PERSISTENT))
            };
            if let Some(i) = self.nets.iter().position(|n| *n == net) {
                self.nets.remove(i);
                what = format!("ignoreip without {}", net);
            } else {
                what = format!("ignoreip with {}", net);
                self.nets.push(net);
            }
            let new = ignore_line(&self.nets, self.name.is_some());
            self.h.ini = self
                .h
                .ini
                .replace(&format!("{}\n", old), &format!("{}\n", new));
        }
        self.note(format!("restart, {}", what));
        self.h.restart();
        self.instance += 1;
        self.configs.push(self.nets.clone());
        self.health = Health::default();
        self.last_bypass = None;
        self.started_at = None;
        // what the engine before knew and had still to send is gone
        self.own_reported = false;
        self.own_notices = 0;
        if let Some(s) = &mut self.safe {
            s.dry_said = false;
        }
        let expected = self.name_lookups(true)?;
        // what the fakes hold before the start, as at the first start
        let listed = self.listed(OWN_TEXT);
        let named = self.named_listed();
        self.expire_safe();
        let safe_before = self.safe_listed();
        self.h.engine.start(self.host as u64);
        self.named_kept(&named, "at the engine start")?;
        self.startup_lines(listed, safe_before, &expected)
    }

    /// Thousands of entries logged while hik-f2b does not poll.
    fn flood(&mut self) -> Result<(), String> {
        let n = self.rng.below(self.p.nvrs as u64) as usize;
        if self.host - self.nvr[n].last_flood < 7400 {
            // one flood per findtime + lookback at most: the window holds
            // what four searches read
            self.host += 30;
            self.note("poll after 30s".to_string());
            return self.cycle();
        }
        self.nvr[n].last_flood = self.host;
        let size = self.rng.range(3300, 7000);
        let rate = self.rng.range(4, 8);
        let duration = size / rate;
        let mut items: Vec<(i64, String, &str, Option<Ipv4Addr>)> = Vec::new();
        for i in 0..size {
            let t = self.host + i / rate;
            if self.rng.chance(80) {
                items.push((t, "192.0.2.40".to_string(), OTHER, None));
            } else {
                let address = format!("192.168.1.{}", 100 + i % 50);
                let ip = address.parse().ok();
                items.push((t, address, FAIL, ip));
            }
        }
        let mut attackers = Vec::new();
        for _ in 0..self.rng.range(0, 2) {
            let address = self.rng.pick(&PERSISTENT);
            let from = self.host + self.rng.range(0, duration / 2);
            for k in 0..self.p.maxretry as i64 + 1 {
                items.push((
                    from + 3 * k,
                    address.to_string(),
                    FAIL,
                    address.parse().ok(),
                ));
            }
            attackers.push(format!("{} from +{}s", address, from - self.host));
        }
        items.sort_by_key(|item| item.0);
        for (t, address, minor, ip) in items {
            self.write(n, t, &address, minor, ip);
        }
        let text = format!(
            "flood {} entries on {} at {}/s over {}s, attackers: {:?}",
            size, self.nvr[n].name, rate, duration, attackers
        );
        self.note(text);
        self.host += duration;
        if self.rng.chance(50) {
            self.restart()?;
        }
        Ok(())
    }

    fn clock(&mut self) -> Result<(), String> {
        let n = self.rng.below(self.p.nvrs as u64) as usize;
        if self.rng.chance(20) {
            return self.outage_then_dst_end(n);
        }
        let skew = self.nvr[n].skew;
        let lookback = self.p.lookback;
        let r = self.rng.below(100);
        let delta = if skew != SKEW && self.rng.chance(40) {
            SKEW - skew
        } else if r < 25 {
            self.rng.range(30, 600)
        } else if r < 35 {
            self.rng.pick(&[1200, 3600])
        } else if r < 75 {
            // mostly more than the time since the last poll: behind the cursor
            -self.rng.range(lookback / 3, lookback)
        } else if r < 87 {
            -3600
        } else {
            // the real-time clock is reset to 2000-01-01
            util::parse_ts("2000-01-01T00:00:00").unwrap() - (self.host + skew)
        };
        self.step_clock(n, delta);
        Ok(())
    }

    fn step_clock(&mut self, n: usize, delta: i64) {
        self.nvr[n].skew += delta;
        self.fake(n).lock().unwrap().skew = self.nvr[n].skew;
        let text = format!("{} clock {:+}s", self.nvr[n].name, delta);
        self.note(text);
    }

    /// An NVR that cannot be reached for about an hour, failed logins
    /// logged on it meanwhile, then the end of DST (-3600 s) before it can
    /// be read again. With `findtime` long enough, its read position trails
    /// the clock by more than an hour, so only the offset shows the step.
    fn outage_then_dst_end(&mut self, n: usize) -> Result<(), String> {
        let was = self.nvr[n].mode;
        self.set_nvr(n, Mode::Down);
        let address = self.rng.pick(&PERSISTENT);
        let count = self.p.maxretry as i64 + 1;
        for i in 0..count {
            let at = self.host + 10 + 5 * i;
            self.write(n, at, address, FAIL, address.parse().ok());
        }
        let text = format!(
            "fail {} {:?} x{} during the outage",
            self.nvr[n].name, address, count
        );
        self.note(text);
        let outage = self.rng.range(3600, 4100);
        let end = self.host + outage;
        while self.host + 300 < end {
            self.host += 300;
            self.note("poll after 300s".to_string());
            self.cycle()?;
        }
        self.host = end;
        self.step_clock(n, -3600);
        self.set_nvr(
            n,
            if was == Mode::Down {
                Mode::Down
            } else {
                Mode::Ok
            },
        );
        Ok(())
    }

    fn settle(&mut self) -> Result<(), String> {
        self.note("settle".to_string());
        if self.router != Router::Ok {
            self.set_router(Router::Ok);
        }
        for n in 0..self.p.nvrs {
            if self.nvr[n].mode != Mode::Ok {
                self.set_nvr(n, Mode::Ok);
            }
        }
        for _ in 0..6 {
            self.host += 30;
            self.cycle()?;
        }
        let mut rounds = 0;
        while self.h.engine.state().ledger.waiting() > 0 && rounds < 48 {
            self.host += 600;
            self.cycle()?;
            rounds += 1;
        }
        for _ in 0..2 {
            self.host += 30;
            self.cycle()?;
        }
        Ok(())
    }

    fn expire_router(&mut self) {
        let now = self.host;
        {
            let mut f = self.h.fake.lock().unwrap();
            for (address, until) in &self.expiry {
                if *until <= now {
                    f.bans.retain(|b| b != address);
                }
            }
        }
        self.expiry.retain(|(_, until)| *until > now);
    }

    /// One engine cycle at the current host time, and the checks after it.
    fn cycle(&mut self) -> Result<(), String> {
        let index = self.cycles.len();
        if self.unsorted {
            for n in 0..self.p.nvrs {
                self.fake(n).lock().unwrap().entries.sort();
            }
            self.unsorted = false;
        }
        self.expire_router();
        self.expire_safe();
        let safe_before = self.safe_listed();
        let router = Arc::clone(&self.h.fake);
        let queries = router.lock().unwrap().rule_queries.len();
        let offsets = self.offsets();
        let own_listed = self.listed(OWN_TEXT);
        let named = self.named_listed();
        self.h.set_host(self.host);
        self.h.engine.cycle_at(self.host as u64);
        self.named_kept(&named, "in a cycle")?;
        let expected = self.name_lookups(false)?;
        let mut about_name = Vec::new();
        let started_at = *self.started_at.get_or_insert(self.host);
        for (n, (before, after)) in offsets.iter().zip(self.offsets()).enumerate() {
            if *before != after {
                self.nvr[n].offset_changes += 1;
            }
        }
        let lines = util::captured_log();
        let (puts, sent, checked) = {
            let mut f = router.lock().unwrap();
            let puts = std::mem::take(&mut f.put_log);
            let sent = std::mem::take(&mut f.tg_sent);
            (puts, sent, f.rule_queries.len() > queries)
        };
        let nvr_ok: Vec<bool> = self.nvr.iter().map(|n| n.mode == Mode::Ok).collect();
        let mut cycle = Cycle {
            host: self.host,
            instance: self.instance,
            nvr_ok,
            router: self.router,
            pending_after: self.h.engine.state().ledger.waiting() > 0,
            transport: false,
            refused: false,
            ban_pass: false,
            router_pass: false,
            notices: Vec::new(),
        };
        let polls: Vec<(String, bool)> = self
            .nvr
            .iter()
            .map(|n| (format!("nvr:{}", n.name), n.mode == Mode::Ok))
            .collect();
        for (key, ok) in polls {
            if ok {
                self.health.pass(&key);
            } else {
                self.health.fail(&key, self.host);
            }
        }
        let mut limited = false;
        let mut check_failed = false;
        let mut notified = Vec::new();
        let mut events = Vec::new();
        let mut own = OwnSeen::default();
        let mut safe = SafeSeen::default();
        let mut sizes = Vec::new();
        own.deletes(&router)?;
        for line in &lines {
            let line = classify(line);
            own.see(&line)?;
            safe.see(&line)?;
            match line {
                Line::NameExempt(ip, name) => {
                    self.named_line(ip, &name, "a failed login said to be exempt")?;
                    events.push(format!("{} exempt", ip));
                }
                Line::NameDropped(ip, name) => {
                    self.named_line(ip, &name, "a drop")?;
                    events.push(format!("{} dropped as named", ip));
                }
                Line::NameLog(text) => about_name.push(text),
                Line::Counted(n, ip, ts) => {
                    self.on_count(n, ip, ts)?;
                    events.push(format!("{}+1", ip));
                }
                Line::Bypass(ip) => {
                    if !self.listed(&ip.to_string()) {
                        return Err(format!(
                            "[health/condition] {} reached the NVR \"already listed\", but the \
                             router does not list it",
                            ip
                        ));
                    }
                    if self.host - started_at <= STARTUP_GRACE {
                        return Err(format!(
                            "[health/model] {} reported as a bypass {} s after the engine \
                             started, within {} s",
                            ip,
                            self.host - started_at,
                            STARTUP_GRACE
                        ));
                    }
                    self.on_ban(ip, Ban::Listed)?;
                    cycle.ban_pass = true;
                    self.health.write_failed = false;
                    self.health.pass("firewall");
                    self.health.pass("ban-refused");
                    self.health.fail("ban-bypassed", self.host);
                    self.last_bypass = Some(self.host);
                    events.push(format!("bypass {}", ip));
                }
                Line::Ban(ip, kind) => {
                    self.on_ban(ip, kind)?;
                    if kind != Ban::Listed {
                        notified.push(ip);
                    }
                    if kind != Ban::Reported {
                        cycle.ban_pass = true;
                        self.health.write_failed = false;
                        self.health.pass("firewall");
                        self.health.pass("ban-refused");
                    }
                    events.push(format!("{:?} {}", kind, ip));
                }
                Line::Transport(ip) => {
                    self.on_request(ip, "ban request")?;
                    cycle.transport = true;
                    self.health.write_failed = true;
                    self.health.fail("firewall", self.host);
                    events.push(format!("unreachable for {}", ip));
                }
                Line::Refused(ip) => {
                    self.on_request(ip, "ban request")?;
                    cycle.refused = true;
                    self.health.write_failed = false;
                    self.health.fail("ban-refused", self.host);
                    events.push(format!("refused {}", ip));
                }
                Line::CheckFailed => check_failed = true,
                Line::Limited => {
                    limited = true;
                    self.health.fail("rate-limit", self.host);
                    events.push("rate limit".to_string());
                }
                Line::Dropped(ip) => {
                    self.dropped.insert(ip);
                    events.push(format!("dropped {}", ip));
                }
                Line::Skipped(n, from, to) => {
                    for g in self.gens.iter_mut() {
                        if g.nvr == n && g.seq <= index && (from..=to).contains(&g.device) {
                            g.lost = true;
                        }
                    }
                    events.push(format!("nvr{} skipped", n + 1));
                }
                Line::SkippedAll(n) => {
                    for g in self.gens.iter_mut() {
                        if g.nvr == n && g.seq <= index {
                            g.lost = true;
                        }
                    }
                    events.push(format!("nvr{} skipped within a second", n + 1));
                }
                Line::Notice(notice) => {
                    events.push(notice.clone());
                    cycle.notices.push(notice);
                }
                Line::OwnLogin(_)
                | Line::OwnRemoved(_)
                | Line::OwnDryRun(_)
                | Line::OwnStuck(_)
                | Line::OwnAskFailed
                | Line::SafeDry(_)
                | Line::SafeAdded(_)
                | Line::SafeWriteFailed(_)
                | Line::SafeRuleOk
                | Line::SafeRuleFailed
                | Line::SafeOther
                | Line::Other => {}
                Line::ListSize(list, n) => sizes.push(Some((list, n))),
                Line::ListSizeFailed => sizes.push(None),
            }
        }
        for (address, outcome) in puts {
            let ip: Ipv4Addr = match address.parse() {
                Ok(ip) => ip,
                Err(_) => return Err(format!("[router] a ban request for {:?}", address)),
            };
            self.on_request(ip, "ban request")?;
            if !["refused", "down", "status"].contains(&outcome) {
                cycle.router_pass = true;
            }
        }
        self.name_logged(&about_name, &expected)?;
        if !expected.is_empty() {
            if let Some(n) = &self.name {
                events.push(format!("{} -> {}", NAME, and_list(&n.known)));
            }
        }
        if !limited && !cycle.transport {
            self.health.pass("rate-limit");
        }
        let all_read = cycle.nvr_ok.iter().all(|ok| *ok);
        if let Some(last) = self.last_bypass {
            if all_read && self.host - last >= self.p.alert_after {
                self.health.pass("ban-bypassed");
                self.last_bypass = None;
            }
        }
        if !cycle.pending_after {
            self.health.withdraw("ban-refused");
        }
        if check_failed {
            self.health.write_failed = false;
            self.health.fail("firewall", self.host);
        } else if checked {
            // A check that works ends a problem that only bans showed only
            // when no ban is left to show it: it is withdrawn.
            if !self.health.write_failed {
                cycle.router_pass = true;
                self.health.pass("firewall");
            } else if !cycle.pending_after {
                cycle.router_pass = true;
                self.health.write_failed = false;
                self.health.withdraw("firewall");
            }
            self.health.pass("firewall-rule");
        }
        // no count of the address-list in a cycle
        self.count_checked(false, &sizes)?;
        // the write of the safe list and the look-up of the own address
        // follow a check that the router answered
        self.safe_checked(checked, safe_before, &safe)?;
        self.own_swept(checked, own_listed, &own)?;
        if own.logins > 0 {
            events.push(format!("{} own failed login(s) not counted", own.logins));
        }
        if (cycle.transport || check_failed) && self.router != Router::Unreachable {
            return Err(format!(
                "[health/condition] the firewall was found unreachable while the router was {:?}",
                self.router
            ));
        }
        if cycle.refused && self.router != Router::Refusing {
            return Err(format!(
                "[health/condition] a ban was refused while the router was {:?}",
                self.router
            ));
        }
        let mut expected = self.health.due(self.host, self.p.alert_after);
        expected.sort();
        let mut actual = cycle.notices.clone();
        actual.sort();
        if expected != actual {
            return Err(format!(
                "[health/model] health notices {:?}, expected {:?}",
                actual, expected
            ));
        }
        let mut announced = Vec::new();
        let mut own_sent = 0;
        for body in &sent {
            if let Some(ip) = ban_notice(body) {
                announced.push(ip);
            }
            if own_notice(body) {
                own_sent += 1;
            }
        }
        if own_sent != self.own_notices {
            return Err(format!(
                "[own/notify] {} notification(s) about {} in the address-list, expected {}",
                own_sent, OWN_TEXT, self.own_notices
            ));
        }
        self.own_notices = 0;
        announced.sort();
        notified.sort();
        if announced != notified {
            return Err(format!(
                "[notify] ban notifications for {:?}, but bans and reports for {:?}",
                announced, notified
            ));
        }
        if !events.is_empty() {
            self.note(format!("  -> {}", events.join(", ")));
        }
        self.cycles.push(cycle);
        let state = self.h.engine.state();
        let started: Vec<usize> = (0..self.p.nvrs)
            .filter(|&n| !self.nvr[n].started && state.cursors.get(&self.nvr[n].name).is_some())
            .collect();
        for n in started {
            self.nvr[n].started = true;
            let text = format!("  -> {} started", self.nvr[n].name);
            self.note(text);
        }
        self.check_state()
    }

    /// The offset the engine stores for each NVR.
    fn offsets(&self) -> Vec<Option<i64>> {
        self.nvr
            .iter()
            .map(|n| {
                self.h
                    .engine
                    .state()
                    .cursors
                    .get(&n.name)
                    .and_then(|st| st.offset())
            })
            .collect()
    }

    fn on_count(&mut self, n: usize, ip: Ipv4Addr, ts: i64) -> Result<(), String> {
        self.named_exempt(ip, "a counted failed login")?;
        if exempt(&self.nets, ip) {
            return Err(format!(
                "[safety/exempt] a failed login of {} was counted, which is exempt under {}",
                ip,
                ignore_line(&self.nets, self.name.is_some())
            ));
        }
        // The engine converts with the NVR's offset at this poll, which is
        // the fake's skew now.
        let device = ts + self.nvr[n].skew;
        let counted = self.counted.entry((n, ip, device)).or_insert(0);
        *counted += 1;
        let counted = *counted as usize;
        let hosts = self
            .generated
            .get(&(n, ip, device))
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let logged = hosts.len();
        // count/shift: by the entry it can best be (several can share a
        // device time after a clock went back)
        let changes = self.nvr[n].offset_changes;
        let excess = hosts
            .iter()
            .map(|g| {
                let shift = ts - g.host;
                let at_logging = device - g.host;
                let allowed = match g.stored {
                    Some(stored) => {
                        (at_logging - stored).abs()
                            + CLOCK_JUMP * (changes - g.changes).max(1) as i64
                    }
                    None => i64::MAX,
                };
                shift.abs().saturating_sub(allowed)
            })
            .min();
        if let Some(excess) = excess.filter(|e| *e > 0) {
            return Err(format!(
                "[count/shift] the failed login of {} at {} (device time) on {} was counted at \
                 {}, {} s further from its true host time than the engine allows",
                ip,
                util::fmt_ts(device),
                self.nvr[n].name,
                util::fmt_ts(ts),
                excess
            ));
        }
        if counted > logged {
            let before = self
                .gens
                .iter()
                .any(|g| g.nvr == n && g.ip == Some(ip) && g.device == device && !g.after_start);
            let tag = if before && logged == 0 {
                "count/prestart"
            } else {
                "count/double"
            };
            return Err(format!(
                "[{}] the failed login of {} at {} (device time) on {} was counted {} time(s), \
                 logged {} time(s) after the first start",
                tag,
                ip,
                util::fmt_ts(device),
                self.nvr[n].name,
                counted,
                logged
            ));
        }
        // Several entries can share a device time after the clock went back;
        // the largest shift of them is the safe one to assume.
        let shift = hosts.iter().map(|g| ts - g.host).max().unwrap_or(0);
        let largest = self.shift.entry(ip).or_insert(0);
        *largest = (*largest).max(shift);
        Ok(())
    }

    /// `name/exempt`: `what` happened for `ip` while the name resolves to it
    /// for the engine running now.
    fn named_exempt(&self, ip: Ipv4Addr, what: &str) -> Result<(), String> {
        match &self.name {
            Some(n) if n.known.contains(&ip) => Err(format!(
                "[name/exempt] {} for {} while {} resolves to {} for the engine",
                what,
                ip,
                NAME,
                and_list(&n.known)
            )),
            _ => Ok(()),
        }
    }

    /// `name/line`: a line that says `ip` is exempt for the `ignoreip` name
    /// `name`.
    fn named_line(&self, ip: Ipv4Addr, name: &str, what: &str) -> Result<(), String> {
        match &self.name {
            Some(n) if name == NAME && n.known.contains(&ip) => Ok(()),
            Some(n) => Err(format!(
                "[name/line] {} for {} as {}, but {} resolves to {} for the engine",
                what,
                ip,
                name,
                NAME,
                and_list(&n.known)
            )),
            None => Err(format!(
                "[name/line] {} for {} as {}, without a name in ignoreip",
                what, ip, name
            )),
        }
    }

    /// The addresses the name resolves to, or once did, that are in the
    /// address-list now (`name/kept`).
    fn named_listed(&self) -> Vec<String> {
        match &self.name {
            Some(n) => n
                .ever
                .iter()
                .map(|ip| ip.to_string())
                .filter(|a| self.listed(a))
                .collect(),
            None => Vec::new(),
        }
    }

    /// `name/kept`: each of `before` is still in the address-list.
    fn named_kept(&self, before: &[String], when: &str) -> Result<(), String> {
        for address in before {
            if !self.listed(address) {
                return Err(format!(
                    "[name/kept] {}, which {} resolves to or did, left the address-list {}",
                    address, NAME, when
                ));
            }
        }
        Ok(())
    }

    /// The look-ups of the name since the last call: `name/interval`, and
    /// the lines they must log (`name/log`), each a prefix. `start`: an
    /// engine was started.
    fn name_lookups(&mut self, start: bool) -> Result<Vec<String>, String> {
        let resolved = self.h.own.resolved();
        let host = self.host;
        let Some(n) = &mut self.name else {
            if resolved != 0 {
                return Err(format!(
                    "[name/interval] {} look-up(s) without a name in ignoreip",
                    resolved
                ));
            }
            return Ok(Vec::new());
        };
        let new = resolved - n.resolved;
        n.resolved = resolved;
        if start {
            if new != 1 {
                return Err(format!(
                    "[name/interval] {} look-up(s) at an engine start, expected 1",
                    new
                ));
            }
            return Ok(n.started());
        }
        let due = match n.since {
            None => {
                n.since = Some(host);
                false
            }
            Some(since) => host < since || host - since >= RESOLVE_EVERY as i64,
        };
        if new != usize::from(due) {
            return Err(format!(
                "[name/interval] {} look-up(s) in a poll {} s after the last one, expected {}",
                new,
                n.since.map_or(0, |since| host - since),
                usize::from(due)
            ));
        }
        if !due {
            return Ok(Vec::new());
        }
        n.since = Some(host);
        Ok(n.looked_up())
    }

    /// `name/log`: the lines about the name are `expected` (prefixes).
    fn name_logged(&self, seen: &[String], expected: &[String]) -> Result<(), String> {
        let matches = seen.len() == expected.len()
            && seen
                .iter()
                .zip(expected)
                .all(|(line, want)| line.starts_with(want));
        if !matches {
            return Err(format!(
                "[name/log] lines about the name {:?}, expected {:?}",
                seen, expected
            ));
        }
        Ok(())
    }

    /// A name event: the answer for `NAME` changes, failed logins come from
    /// one of `NAMED`, or one of them is put into the address-list by hand.
    /// Drawn from the name's own generator.
    fn name_event(&mut self) {
        let r = self.name_rng.below(100);
        if r < 45 {
            let answer = draw_answer(&mut self.name_rng);
            self.h.own.set_name(NAME, answer.clone());
            self.note(format!("{} answers {:?}", NAME, answer));
            if let Some(n) = &mut self.name {
                n.answer = answer;
            }
            return;
        }
        let address = NAMED[self.name_rng.below(2) as usize];
        let ip: Ipv4Addr = address.parse().unwrap();
        if r < 88 || self.p.report_once() {
            let n = self.name_rng.below(self.p.nvrs as u64) as usize;
            let count = self.name_rng.range(1, self.p.maxretry as i64 + 2);
            let gap = self.name_rng.range(1, 10);
            let user = self.name_rng.pick(&USERS);
            // the drop rule keeps a listed address away from the NVR, mostly
            if !self.p.report_once() && self.listed(address) && self.name_rng.chance(85) {
                self.note(format!("{} blocked by the router", address));
                return;
            }
            for i in 0..count {
                self.write_as(n, self.host + i * gap, address, FAIL, Some(ip), user);
            }
            self.host += (count - 1) * gap;
            let text = format!(
                "fail {} {:?} (named) user {:?} x{} every {}s",
                self.nvr[n].name, address, user, count, gap
            );
            self.note(text);
            return;
        }
        if !self.listed(address) {
            self.h.fake.lock().unwrap().bans.push(address.to_string());
        }
        if let Some(n) = &mut self.name {
            if !n.ever.contains(&ip) {
                n.ever.push(ip);
            }
        }
        self.note(format!("router: {} listed by hand", address));
    }

    /// A ban request or report for `ip`: exempt, or not backed by the log?
    fn on_request(&self, ip: Ipv4Addr, what: &str) -> Result<(), String> {
        self.named_exempt(ip, what)?;
        if exempt(&self.nets, ip) {
            return Err(format!(
                "[safety/exempt] {} for {}, which is exempt under {}",
                what,
                ip,
                ignore_line(&self.nets, self.name.is_some())
            ));
        }
        // 0 unless a device clock changed between logging and counting
        let slack = self.shift.get(&ip).copied().unwrap_or(0);
        let seq = self.cycles.len();
        let mut times: Vec<i64> = Vec::new();
        for &i in self.by_ip.get(&ip).map(Vec::as_slice).unwrap_or(&[]) {
            let g = &self.gens[i];
            if g.after_start && g.seq <= seq {
                times.push(g.host);
            }
        }
        times.sort_unstable();
        let m = self.p.maxretry;
        let span = self.p.findtime + slack;
        if !times.windows(m).any(|w| w[m - 1] - w[0] <= span) {
            return Err(format!(
                "[safety/maxretry] {} for {}, which has no {} failed logins within {} s after \
                 the first start (logged at {:?})",
                what,
                ip,
                m,
                span,
                times.iter().map(|t| t - self.t0).collect::<Vec<_>>()
            ));
        }
        Ok(())
    }

    fn on_ban(&mut self, ip: Ipv4Addr, kind: Ban) -> Result<(), String> {
        self.on_request(ip, &format!("{:?}", kind))?;
        let now = self.host;
        if kind != Ban::Listed {
            let recent = self
                .bans
                .iter()
                .filter(|(t, _, k)| *k != Ban::Listed && now - *t < 3600)
                .count();
            if recent + 1 > self.p.max_per_hour {
                return Err(format!(
                    "[safety/rate] {} bans or reports within an hour, limit {}",
                    recent + 1,
                    self.p.max_per_hour
                ));
            }
        }
        let last = self
            .bans
            .iter()
            .rev()
            .find(|(_, b, k)| *b == ip && *k == kind)
            .map(|(t, _, _)| *t);
        if let Some(last) = last {
            let period = match kind {
                Ban::Reported => Some(self.p.keep()),
                Ban::Accepted => Some(self.p.bantime.unwrap_or(i64::MAX)),
                Ban::Listed => None,
            };
            if period.is_some_and(|period| now - last < period) {
                return Err(format!(
                    "[liveness/once] {} {:?} again {} s after the last time",
                    ip,
                    kind,
                    now - last
                ));
            }
        }
        if let (Ban::Accepted, Some(bantime)) = (kind, self.p.bantime) {
            self.expiry.push((ip.to_string(), now + bantime));
        }
        self.bans.push((now, ip, kind));
        Ok(())
    }

    fn check_state(&self) -> Result<(), String> {
        let state = self.h.engine.state();
        if State::parse(&state.serialize()) != *state {
            return Err("[state] the state does not load back from its file format".to_string());
        }
        let held = state.ledger.sizes();
        let cap = Ledger::caps(self.p.maxretry, self.p.max_per_hour);
        let caps = [
            ("tracked addresses", held.tracked, cap.tracked),
            ("failure times", held.fail_times, cap.fail_times),
            ("remembered bans", held.remembered, cap.remembered),
            ("waiting bans", held.waiting, cap.waiting),
            ("recent bans", held.recent_bans, cap.recent_bans),
            (
                "queued notifications",
                self.h.engine.queued_notifications(),
                100,
            ),
        ];
        for (what, n, cap) in caps {
            if n > cap {
                return Err(format!("[caps] {} {} > {}", n, what, cap));
            }
        }
        if held.most_fail_times > cap.most_fail_times {
            return Err(format!(
                "[caps] {} failure times for one address",
                held.most_fail_times
            ));
        }
        for (name, st) in state.cursors.iter() {
            if st.seen() > MAX_SEEN {
                return Err(format!("[caps] {} seen entries for {}", st.seen(), name));
            }
        }
        Ok(())
    }

    /// See `health/stretch` in the module comment.
    fn check_stretches(&self, key: &str, mode: Router) -> Result<(), String> {
        let alert = format!("alert {}", key);
        let refused = mode == Router::Refusing;
        let cycles = &self.cycles;
        let mut i = 0;
        while i < cycles.len() {
            let c0 = &cycles[i];
            let observed = if refused {
                c0.refused && !c0.ban_pass
            } else {
                c0.transport
            };
            if c0.router != mode || !c0.pending_after || !observed {
                i += 1;
                continue;
            }
            let mut k = i;
            while k + 1 < cycles.len() {
                let c = &cycles[k + 1];
                let same = c.instance == c0.instance && c.router == mode;
                if !same || !c.pending_after || c.ban_pass {
                    break;
                }
                k += 1;
            }
            let due = c0.host + self.p.alert_after;
            if cycles[k].host >= due {
                let t = (i..=k).find(|&j| cycles[j].host >= due).unwrap();
                // the problem may have been opened before c0, after the
                // last time it was seen to pass
                let mut s = i;
                while s > 0 {
                    let c = &cycles[s - 1];
                    let closes = if refused {
                        c.ban_pass || !c.pending_after
                    } else {
                        c.router_pass
                    };
                    if c.instance != c0.instance || closes {
                        break;
                    }
                    s -= 1;
                }
                if !cycles[s..=t].iter().any(|c| c.notices.contains(&alert)) {
                    return Err(format!(
                        "[health/stretch] router {:?} kept a ban waiting from +{}s to +{}s \
                         (alert_after {} s), but no {:?} by +{}s",
                        mode,
                        c0.host - self.t0,
                        cycles[k].host - self.t0,
                        self.p.alert_after,
                        alert,
                        cycles[t].host - self.t0
                    ));
                }
            }
            i = k + 1;
        }
        Ok(())
    }

    /// See `liveness` in the module comment.
    fn check_liveness(&self) -> Result<usize, String> {
        let mut musts = 0;
        let polls: Vec<Vec<usize>> = (0..self.p.nvrs)
            .map(|n| {
                (0..self.cycles.len())
                    .filter(|&c| self.cycles[c].nvr_ok[n])
                    .collect()
            })
            .collect();
        let window = self.p.findtime + self.p.lookback;
        let addresses = PERSISTENT.iter().chain(&OCCASIONAL).chain(&OWNERS);
        for address in addresses {
            let ip: Ipv4Addr = address.parse().unwrap();
            let excused =
                self.configs.iter().any(|nets| exempt(nets, ip)) || self.dropped.contains(&ip);
            if excused {
                continue;
            }
            // (host time, latest host time at which it is read)
            let mut entries: Vec<(i64, i64)> = Vec::new();
            for &i in self.by_ip.get(&ip).map(Vec::as_slice).unwrap_or(&[]) {
                let g = &self.gens[i];
                if !g.after_start || g.lost {
                    continue;
                }
                let times = &self.nvr[g.nvr].times;
                let backlog = times.partition_point(|&t| t <= g.host)
                    - times.partition_point(|&t| t <= g.host - window);
                let ok = &polls[g.nvr];
                let first = ok.partition_point(|&c| c < g.seq);
                if let Some(&c) = ok.get(first + backlog.div_ceil(PER_POLL) - 1) {
                    entries.push((g.host, self.cycles[c].host));
                }
            }
            entries.sort_unstable();
            let m = self.p.maxretry;
            let mut start = None;
            for (i, &(host, _)) in entries.iter().enumerate() {
                let n = entries[i..]
                    .iter()
                    .filter(|(_, read)| *read <= host + self.p.findtime)
                    .count();
                if n >= m {
                    start = Some(host);
                }
            }
            let Some(start) = start else {
                continue;
            };
            musts += 1;
            let keep = self.p.keep();
            let done = if self.p.report_once() {
                self.bans
                    .iter()
                    .any(|(t, b, k)| *b == ip && *k == Ban::Reported && *t + keep > start)
            } else {
                self.bans
                    .iter()
                    .any(|(t, b, k)| *b == ip && *k != Ban::Reported && *t >= start)
            };
            if !done {
                return Err(format!(
                    "[liveness] {} had {} failed logins from +{}s on that had to be read within \
                     findtime, but was not {} after that",
                    ip,
                    m,
                    start - self.t0,
                    if self.p.report_once() {
                        "reported"
                    } else {
                        "banned"
                    }
                ));
            }
        }
        Ok(musts)
    }

    fn report(&self, violation: &str) -> String {
        let shown = self.trace.len().min(TRACE_LINES);
        format!(
            "{}\nseed {}, class {:?}: {}\nreplay: HIK_F2B_SIM_SEED={} cargo test --test sim -- \
             --nocapture\ntrace (last {} of {} lines):\n{}",
            violation,
            self.seed,
            self.p.class,
            self.p.describe(),
            self.seed,
            shown,
            self.trace.len(),
            self.trace[self.trace.len() - shown..].join("\n")
        )
    }
}

/// `hh:mm:ss` or `NdHH:MM:SS`, as hik-f2b writes a timeout, in seconds.
fn seconds(text: &str) -> Option<i64> {
    let (days, hms) = match text.split_once('d') {
        Some((d, rest)) => (d.parse::<i64>().ok()?, rest),
        None => (0, text),
    };
    let parts: Vec<i64> = hms
        .split(':')
        .map(|p| p.parse().ok())
        .collect::<Option<_>>()?;
    match parts.as_slice() {
        [h, m, s] => Some(days * 86400 + h * 3600 + m * 60 + s),
        _ => None,
    }
}

fn env(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.trim().parse().ok())
}

/// The seeds of `class` in this run (see the module comment).
fn seeds(class: Class) -> Vec<u64> {
    let count = CLASSES.len() as u64;
    let index = CLASSES.iter().position(|c| *c == class).unwrap() as u64;
    if let Some(seed) = env("HIK_F2B_SIM_SEED") {
        return if seed % count == index {
            vec![seed]
        } else {
            Vec::new()
        };
    }
    let default = if class == Class::Backlog {
        DEFAULT_SEEDS / 3
    } else {
        DEFAULT_SEEDS
    };
    let n = env("HIK_F2B_SIM_SEEDS").unwrap_or(default);
    let start = env("HIK_F2B_SIM_START").unwrap_or(1);
    let first = start + (index + count - start % count) % count;
    (0..n).map(|i| first + i * count).collect()
}

fn panic_text(panic: &(dyn std::any::Any + Send)) -> String {
    if let Some(text) = panic.downcast_ref::<&str>() {
        text.to_string()
    } else if let Some(text) = panic.downcast_ref::<String>() {
        text.clone()
    } else {
        "(no message)".to_string()
    }
}

/// Straight to stdout, past the test harness's capture.
fn say(text: &str) {
    for line in text.lines() {
        util::log("SIM", line);
    }
}

fn run_class(class: Class) {
    util::capture_log();
    let started = Instant::now();
    let replay = env("HIK_F2B_SIM_SEED").is_some();
    let seeds = seeds(class);
    let mut failures = Vec::new();
    // cycles, accepted, listed, reported, alerts, liveness, shifted, bypass
    // alerts, own address removed, own address reported in a dry run,
    // scenarios with a safe list, writes to it, scenarios with a name in
    // ignoreip, its look-ups and changes, bans and reports of its addresses
    // (after they left its answer)
    let mut stats = [0usize; 16];
    for &seed in &seeds {
        let mut sim = Sim::new(seed);
        let result = match catch_unwind(AssertUnwindSafe(|| sim.run())) {
            Ok(result) => result,
            Err(panic) => Err(format!("[panic] {}", panic_text(&*panic))),
        };
        let _ = util::captured_log();
        let count = |kind: Ban| sim.bans.iter().filter(|(_, _, k)| *k == kind).count();
        let alerts = sim
            .cycles
            .iter()
            .flat_map(|c| &c.notices)
            .filter(|n| n.starts_with("alert "))
            .count();
        let seen = [
            sim.cycles.len(),
            count(Ban::Accepted),
            count(Ban::Listed),
            count(Ban::Reported),
            alerts,
            sim.musts,
            sim.shift.values().filter(|s| **s > 0).count(),
            sim.cycles
                .iter()
                .flat_map(|c| &c.notices)
                .filter(|n| *n == "alert ban-bypassed")
                .count(),
            sim.own_removed,
            sim.own_kept,
            usize::from(sim.safe.is_some()),
            sim.safe.as_ref().map_or(0, |s| s.writes),
            usize::from(sim.name.is_some()),
            sim.name.as_ref().map_or(0, |n| n.lookups),
            sim.name.as_ref().map_or(0, |n| n.changes),
            sim.bans
                .iter()
                .filter(|(_, ip, k)| *k != Ban::Listed && NAMED.contains(&ip.to_string().as_str()))
                .count(),
        ];
        for (total, n) in stats.iter_mut().zip(seen) {
            *total += n;
        }
        match result {
            Err(violation) => failures.push(sim.report(&violation)),
            Ok(()) if replay => say(&sim.report("no violation")),
            Ok(()) => {}
        }
    }
    fake::sample_conntrack();
    let conntrack = fake::conntrack_peak();
    let summary = format!(
        "sim {:?}: {} seed(s), {} cycles, {:.1} s, {} violation(s); bans {}, already listed {}, \
         reports {}, health alerts {} (ban-bypassed {}), addresses due for liveness {}, \
         addresses with a shift {}, own address removed {} (reported in a dry run {}), safe \
         list in {} scenario(s) ({} write(s)), ignoreip name in {} scenario(s) ({} look-up(s), \
         {} change(s), {} ban(s) or report(s) of its addresses); peak fake threads {} (at most {}){}",
        class,
        seeds.len(),
        stats[0],
        started.elapsed().as_secs_f64(),
        failures.len(),
        stats[1],
        stats[2],
        stats[3],
        stats[4],
        stats[7],
        stats[5],
        stats[6],
        stats[8],
        stats[9],
        stats[10],
        stats[11],
        stats[12],
        stats[13],
        stats[14],
        stats[15],
        fake::peak_threads(),
        MAX_FAKE_THREADS,
        conntrack
            .map(|(count, max)| format!("; connection tracking peak {} of {}", count, max))
            .unwrap_or_default()
    );
    say(&summary);
    for failure in &failures {
        say(failure);
    }
    // A fault of the environment, which can also cause the violations.
    if let Some((count, max)) = conntrack.filter(|(count, max)| count >= max) {
        panic!(
            "{}\n\nsim {:?}: the kernel's connection tracking table was full ({} of {} \
             entries), so it dropped new connections: requests to the fakes timed out and this \
             run does not hold (a fault of the environment, not of the engine; see sim.yml)\
             \n\n{}",
            summary,
            class,
            count,
            max,
            failures.join("\n\n")
        );
    }
    if STRICT && !failures.is_empty() {
        panic!("{}\n\n{}", summary, failures.join("\n\n"));
    }
    // A fault of the test harness, not a finding about the engine.
    let peak = fake::peak_threads();
    assert!(
        peak <= MAX_FAKE_THREADS,
        "sim {:?}: the fakes had {} threads at once, more than {}: the test harness does not \
         end the threads of dropped harnesses (a fault of the test, not of the engine)",
        class,
        peak,
        MAX_FAKE_THREADS
    );
    assert_eq!(
        fake::accept_errors(),
        0,
        "sim {:?}: accepts failed on the fakes' listeners (a fault of the test harness)",
        class
    );
}

#[test]
fn sim_firewall() {
    run_class(Class::Firewall);
}

#[test]
fn sim_backlog() {
    run_class(Class::Backlog);
}

#[test]
fn sim_dry_run() {
    run_class(Class::DryRun);
}

#[test]
fn sim_notify_only() {
    run_class(Class::NotifyOnly);
}

#[test]
fn sim_clock() {
    run_class(Class::Clock);
}
