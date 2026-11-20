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
//!   change, an RTC reset to 2000-01-01 and its correction.
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
//!   at that moment, or a range that is never banned). Exemption is computed
//!   here, not by the engine.
//! - `safety/maxretry` (all): every ban request or report for an address is
//!   backed by `maxretry` failed logins of it, logged after its NVR's first
//!   start, within a `findtime` span (true host time, from the generated
//!   log). In `Clock` the span may be longer by the clock steps (capped at
//!   `900 + lookback` each, the size below which a step is not a jump) plus
//!   the 5 minutes the engine accepts in the future: an entry read after a
//!   step that is not a jump is converted with the new offset.
//! - `safety/rate` (all): at most `max_bans_per_hour` bans and reports in
//!   any hour, across restarts.
//! - `state` (all): the state loads back from its file format to the same
//!   state after every cycle (and through the file on every restart);
//!   `caps` (all): the bounded collections stay within their bounds.
//! - `panic` (all): no panic.
//! - `count/prestart`, `count/double` (all but `Clock`): each failed login
//!   counted (the engine's `[n/maxretry]` log line) matches a generated one
//!   of the same NVR, address and host time, logged after the first start,
//!   at most once. In `Clock` host times can be off by a step, so the check
//!   is per NVR and address: never more counted than logged after the start.
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
//! - `health/model` (all): the health notices of each cycle are exactly the
//!   ones the documented policy gives for what the engine observed (failed
//!   and successful polls, ban attempts, firewall checks, the rate limit):
//!   alert once after `alert_after`, reminder after 24 h, one recovery or
//!   "unknown" when an alerted problem ends, nothing for a short one, state
//!   lost on restart. `health/condition` (all): an unreachable firewall is
//!   observed only while the router is unreachable, a refused ban only while
//!   it refuses writes. `health/stretch` (`Firewall`, `Backlog`): when the
//!   router keeps a waiting ban from being applied for `alert_after`
//!   (unreachable, or refusing), the alert has been sent by the first cycle
//!   after that.
//!
//! Excluded case: a device clock corrected back by less than `lookback`
//! (not a jump) can move the read window back, and the engine then counts
//! entries again; see the ignored test
//! `small_backward_correction_below_lookback_is_not_recounted` in
//! `tests/e2e.rs`. Addresses with entries in such a re-read stretch are left
//! out of `safety/maxretry`, `count/double` and `liveness`.
//!
//! Environment: `HIK_F2B_SIM_SEEDS` (seeds per class, default
//! `DEFAULT_SEEDS`), `HIK_F2B_SIM_START` (first seed, default 1),
//! `HIK_F2B_SIM_SEED` (run only that seed, in its class, and print its
//! trace). A violation prints the seed, the class, the parameters and the
//! last steps of the trace.

#[path = "support/fake.rs"]
mod fake;

use fake::{Entry, Fake, Harness, Opts, SKEW};
use hik_f2b::state::{State, MAX_PENDING, MAX_SEEN, MAX_TRACKED};
use hik_f2b::util;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Seeds per class when `HIK_F2B_SIM_SEEDS` is not set.
const DEFAULT_SEEDS: u64 = 10;
/// Whether a violation fails the test (otherwise it is only printed).
const STRICT: bool = false;
/// Trace lines shown with a violation.
const TRACE_LINES: usize = 150;
/// New entries an oldest-first poll reads at least: 3200 a search (50 pages
/// of 64 on the fake) less an overlap of at most 120 s at 12 entries a
/// second.
const PER_POLL: usize = 1600;

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

    fn general(&self, nets: &[String]) -> String {
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
            ignore_line(nets)
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

fn ignore_line(nets: &[String]) -> String {
    format!("ignoreip = {}", nets.join(", "))
}

fn in_net(ip: Ipv4Addr, net: &str) -> bool {
    let (addr, len) = net.split_once('/').unwrap_or((net, "32"));
    let addr: Ipv4Addr = addr.parse().unwrap();
    let len: u32 = len.parse().unwrap();
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    u32::from(ip) & mask == u32::from(addr) & mask
}

/// Never banned under `nets`, by the README's list.
fn exempt(nets: &[String], ip: Ipv4Addr) -> bool {
    let first = ip.octets()[0];
    ip.is_loopback()
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
}

struct NvrSim {
    name: String,
    mode: Mode,
    skew: i64,
    started: bool,
    last_flood: i64,
    /// Host times of its entries, in the order written (ascending).
    times: Vec<i64>,
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
    /// The router answered a check or accepted a ban.
    router_pass: bool,
    notices: Vec<String>,
}

/// The health policy of the README, fed with what the engine observed.
#[derive(Default)]
struct Health {
    /// key -> (since, last alert or reminder)
    open: BTreeMap<String, (i64, Option<i64>)>,
    closed: Vec<String>,
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
    Transport(Ipv4Addr),
    Refused(Ipv4Addr),
    CheckFailed,
    Limited,
    Dropped(Ipv4Addr),
    Skipped(usize, i64, i64),
    SkippedAll(usize),
    Notice(String),
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

/// The address a ban notification is about.
fn ban_notice(body: &str) -> Option<Ipv4Addr> {
    let text = fake::text_of(body);
    let rest = text.strip_prefix("\u{26d4} hik-f2b: ")?;
    rest.split(' ').next()?.parse().ok()
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
    /// (nvr, address, host time) of the entries logged after the start.
    generated: HashMap<(usize, Ipv4Addr, i64), u32>,
    counted: HashMap<(usize, Ipv4Addr, i64), u32>,
    generated_total: HashMap<(usize, Ipv4Addr), u32>,
    counted_total: HashMap<(usize, Ipv4Addr), u32>,
    /// Addresses with entries in a stretch that is read again (the excluded
    /// case, see the module comment).
    recount: HashSet<Ipv4Addr>,
    bans: Vec<(i64, Ipv4Addr, Ban)>,
    dropped: HashSet<Ipv4Addr>,
    health: Health,
    slack: i64,
    /// Addresses the liveness check had a due ban or report for.
    musts: usize,
    /// Times the excluded case occurred.
    recounts: usize,
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
        let general: &'static str = Box::leak(p.general(&nets).into_boxed_str());
        let h = Harness::build(Opts {
            telegram: true,
            mikrotik: class != Class::NotifyOnly,
            second_nvr: p.nvrs == 2,
            general,
            ..Default::default()
        });
        let nvr = (0..p.nvrs)
            .map(|n| NvrSim {
                name: format!("nvr{}", n + 1),
                mode: Mode::Ok,
                skew: SKEW,
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
            generated_total: HashMap::new(),
            counted_total: HashMap::new(),
            recount: HashSet::new(),
            bans: Vec::new(),
            dropped: HashSet::new(),
            health: Health::default(),
            slack: 0,
            musts: 0,
            recounts: 0,
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
                *self.generated.entry((n, ip, host)).or_insert(0) += 1;
                *self.generated_total.entry((n, ip)).or_insert(0) += 1;
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
        let text = ignore_line(&self.nets);
        self.note(text);
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
        self.h.engine.startup_check(self.host as u64);
        self.startup_lines()?;
        self.note("first poll".to_string());
        self.cycle()
    }

    /// The log of an engine start: only the firewall check matters.
    fn startup_lines(&mut self) -> Result<(), String> {
        for line in util::captured_log() {
            if matches!(classify(&line), Line::CheckFailed) {
                if self.router != Router::Unreachable {
                    return Err(format!(
                        "[health/condition] the firewall check failed at startup while the \
                         router was {:?}",
                        self.router
                    ));
                }
                self.health.fail("firewall", self.host);
            }
        }
        Ok(())
    }

    fn step(&mut self) -> Result<(), String> {
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
            table.push((6, Kind::Clock));
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
            Kind::Clock => {
                self.clock();
                Ok(())
            }
        }
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
        let old = ignore_line(&self.nets);
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
            let new = ignore_line(&self.nets);
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
        self.h.engine.startup_check(self.host as u64);
        self.startup_lines()
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

    fn clock(&mut self) {
        let n = self.rng.below(self.p.nvrs as u64) as usize;
        let skew = self.nvr[n].skew;
        let lookback = self.p.lookback;
        let r = self.rng.below(100);
        let delta = if skew != SKEW && self.rng.chance(40) {
            SKEW - skew
        } else if r < 25 {
            self.rng.range(30, 600)
        } else if r < 40 {
            self.rng.pick(&[1200, 3600])
        } else if r < 70 {
            -self.rng.range(10, lookback)
        } else if r < 85 {
            -3600
        } else {
            // the real-time clock is reset to 2000-01-01
            util::parse_ts("2000-01-01T00:00:00").unwrap() - (self.host + skew)
        };
        self.nvr[n].skew += delta;
        self.fake(n).lock().unwrap().skew = self.nvr[n].skew;
        self.slack += delta.abs().min(900 + lookback);
        let text = format!("{} clock {:+}s", self.nvr[n].name, delta);
        self.note(text);
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
        while !self.h.engine.state.pending.is_empty() && rounds < 48 {
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

    /// The excluded case: a device clock that went back by less than
    /// `lookback` (so not a jump) and behind the read cursor moves the next
    /// window's start back; entries between the two starts are read again.
    fn check_recount(&mut self, index: usize) {
        let lookback = self.p.lookback;
        for n in 0..self.p.nvrs {
            if self.nvr[n].mode != Mode::Ok {
                continue;
            }
            let since = match self.h.engine.state.nvr.get(&self.nvr[n].name) {
                Some(st) => st.since,
                None => continue,
            };
            let now = self.host + self.nvr[n].skew;
            if !(since - lookback..since).contains(&now) {
                continue;
            }
            let gap = now - lookback..since - lookback;
            let mut hit = Vec::new();
            for g in &self.gens {
                if g.nvr == n && g.seq <= index && gap.contains(&g.device) {
                    hit.extend(g.ip);
                }
            }
            let text = format!(
                "  -> {}: cursor moves back by {}s, re-read: {:?}",
                self.nvr[n].name,
                since - now,
                hit
            );
            self.note(text);
            self.recount.extend(hit);
            self.recounts += 1;
        }
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
        self.check_recount(index);
        let router = Arc::clone(&self.h.fake);
        let queries = router.lock().unwrap().rule_queries.len();
        self.h.set_host(self.host);
        self.h.engine.cycle_at(self.host as u64);
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
            pending_after: !self.h.engine.state.pending.is_empty(),
            transport: false,
            refused: false,
            ban_pass: false,
            router_pass: checked,
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
        for line in &lines {
            match classify(line) {
                Line::Counted(n, ip, ts) => {
                    self.on_count(n, ip, ts)?;
                    events.push(format!("{}+1", ip));
                }
                Line::Ban(ip, kind) => {
                    self.on_ban(ip, kind)?;
                    if kind != Ban::Listed {
                        notified.push(ip);
                    }
                    if kind != Ban::Reported {
                        cycle.ban_pass = true;
                        self.health.pass("firewall");
                        self.health.pass("ban-refused");
                    }
                    events.push(format!("{:?} {}", kind, ip));
                }
                Line::Transport(ip) => {
                    self.on_request(ip, "ban request")?;
                    cycle.transport = true;
                    self.health.fail("firewall", self.host);
                    events.push(format!("unreachable for {}", ip));
                }
                Line::Refused(ip) => {
                    self.on_request(ip, "ban request")?;
                    cycle.refused = true;
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
                Line::Other => {}
            }
        }
        for (address, outcome) in puts {
            let ip: Ipv4Addr = match address.parse() {
                Ok(ip) => ip,
                Err(_) => return Err(format!("[router] a ban request for {:?}", address)),
            };
            self.on_request(ip, "ban request")?;
            if outcome != "refused" && outcome != "down" {
                cycle.router_pass = true;
            }
        }
        if !limited && !cycle.transport {
            self.health.pass("rate-limit");
        }
        if !cycle.pending_after {
            self.health.withdraw("ban-refused");
        }
        if check_failed {
            self.health.fail("firewall", self.host);
        } else if checked {
            self.health.pass("firewall");
            self.health.pass("firewall-rule");
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
        for body in &sent {
            if let Some(ip) = ban_notice(body) {
                announced.push(ip);
            }
        }
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
        let state = &self.h.engine.state;
        let started: Vec<usize> = (0..self.p.nvrs)
            .filter(|&n| !self.nvr[n].started && state.nvr.contains_key(&self.nvr[n].name))
            .collect();
        for n in started {
            self.nvr[n].started = true;
            let text = format!("  -> {} started", self.nvr[n].name);
            self.note(text);
        }
        self.check_state()
    }

    fn on_count(&mut self, n: usize, ip: Ipv4Addr, ts: i64) -> Result<(), String> {
        if exempt(&self.nets, ip) {
            return Err(format!(
                "[safety/exempt] a failed login of {} was counted, which is exempt under {}",
                ip,
                ignore_line(&self.nets)
            ));
        }
        let counted = self.counted.entry((n, ip, ts)).or_insert(0);
        *counted += 1;
        let counted = *counted;
        let total = self.counted_total.entry((n, ip)).or_insert(0);
        *total += 1;
        let total = *total;
        if self.recount.contains(&ip) {
            return Ok(());
        }
        let name = &self.nvr[n].name;
        if self.p.class == Class::Clock {
            let logged = self.generated_total.get(&(n, ip)).copied().unwrap_or(0);
            if total > logged {
                return Err(format!(
                    "[count/double] {} failed logins of {} counted on {}, {} logged after the \
                     first start",
                    total, ip, name, logged
                ));
            }
            return Ok(());
        }
        let logged = self.generated.get(&(n, ip, ts)).copied().unwrap_or(0);
        if counted > logged {
            let before = self
                .gens
                .iter()
                .any(|g| g.nvr == n && g.ip == Some(ip) && g.host == ts && !g.after_start);
            let tag = if before && logged == 0 {
                "count/prestart"
            } else {
                "count/double"
            };
            return Err(format!(
                "[{}] the failed login of {} at {} on {} was counted {} time(s), logged {} \
                 time(s) after the first start",
                tag,
                ip,
                util::fmt_ts(ts),
                name,
                counted,
                logged
            ));
        }
        Ok(())
    }

    /// A ban request or report for `ip`: exempt, or not backed by the log?
    fn on_request(&self, ip: Ipv4Addr, what: &str) -> Result<(), String> {
        if exempt(&self.nets, ip) {
            return Err(format!(
                "[safety/exempt] {} for {}, which is exempt under {}",
                what,
                ip,
                ignore_line(&self.nets)
            ));
        }
        if self.recount.contains(&ip) {
            return Ok(());
        }
        let slack = if self.p.class == Class::Clock {
            self.slack + 300
        } else {
            0
        };
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
        let state = &self.h.engine.state;
        if State::parse(&state.serialize()) != *state {
            return Err("[state] the state does not load back from its file format".to_string());
        }
        let per_address = (self.p.maxretry * 4).max(16);
        let caps = [
            ("tracked addresses", state.fails.len(), MAX_TRACKED),
            ("waiting bans", state.pending.len(), MAX_PENDING),
            ("recent bans", state.recent_bans.len(), self.p.max_per_hour),
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
        for (ip, times) in &state.fails {
            if times.len() > per_address {
                return Err(format!("[caps] {} failure times for {}", times.len(), ip));
            }
        }
        for (name, st) in &state.nvr {
            if st.seen.len() > MAX_SEEN {
                return Err(format!(
                    "[caps] {} seen entries for {}",
                    st.seen.len(),
                    name
                ));
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
            let excused = self.configs.iter().any(|nets| exempt(nets, ip))
                || self.dropped.contains(&ip)
                || self.recount.contains(&ip);
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
    let n = env("HIK_F2B_SIM_SEEDS").unwrap_or(DEFAULT_SEEDS);
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
    // cycles, accepted, listed, reported, alerts, liveness, excluded
    let mut stats = [0usize; 7];
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
            sim.recounts,
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
    let summary = format!(
        "sim {:?}: {} seed(s), {} cycles, {:.1} s, {} violation(s); bans {}, already listed {}, \
         reports {}, health alerts {}, addresses due for liveness {}, excluded re-reads {}",
        class,
        seeds.len(),
        stats[0],
        started.elapsed().as_secs_f64(),
        failures.len(),
        stats[1],
        stats[2],
        stats[3],
        stats[4],
        stats[5],
        stats[6]
    );
    say(&summary);
    for failure in &failures {
        say(failure);
    }
    if STRICT && !failures.is_empty() {
        panic!("{}\n\n{}", summary, failures.join("\n\n"));
    }
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
