//! Health alerts: when to tell someone that hik-f2b is not protecting
//! anything right now.
//!
//! The engine reports what happened in a poll to `Health`: how each NVR
//! read went, how a firewall check round ended (`round.rs`), how each ban
//! attempt ended, how the ban loop ended and the end of the poll. `Health` decides which
//! check that opens, passes or withdraws, keeps the bypass timer and says
//! when the periodic firewall check is due. `Alerts` then decides when a
//! check's state is news. Neither does I/O; both take the host time as an
//! argument, like `Engine::cycle_at`, so the rules can be tested on their
//! own:
//!
//! - a problem is alerted once it has lasted `alert_after`, not before;
//! - while it persists, a reminder at most every `REMIND_EVERY`;
//! - one "recovered" notice when an alerted problem goes away; a problem
//!   that clears before it was alerted produces nothing;
//! - a problem that can no longer be observed is withdrawn: one "unknown"
//!   notice if it was alerted, nothing otherwise, and no more reminders.
//!
//! State is kept in memory only.

use crate::action::HealthError;
use crate::round::{Ended, OwnSwept, SafeWritten};
use crate::util;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

/// How often an alerted problem that persists is reported again.
pub const REMIND_EVERY: u64 = 86400;
/// Time between two health checks of the firewall.
pub const HEALTH_CHECK_INTERVAL: u64 = 300;
/// Longest reason kept for a notice.
const MAX_REASON: usize = 150;
/// Said when every refused ban has expired or been dropped while the
/// problem was alerted: nothing is left to show whether it is over.
const BAN_REFUSED_UNKNOWN: &str = "no refused ban is waiting any more; whether the firewall \
                                   accepts bans is not known until the next ban";
/// Said when the firewall problem was shown only by bans that failed, and
/// a firewall check works after every waiting ban expired or was dropped:
/// nothing is left to show whether bans work.
const FIREWALL_UNKNOWN: &str = "the firewall answers the check, but the last ban failed and no \
                                ban is waiting any more; whether the firewall accepts bans is \
                                not known until the next ban";

/// What is being watched. Each value is one problem with a stable key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Check {
    /// The NVR of that name cannot be read: unreachable, or our login is
    /// rejected.
    Nvr(String),
    /// The firewall cannot be reached, refuses our login or answers with an
    /// error. When only a ban showed it, only a ban that the firewall
    /// answers ends it (see `Health::write_failed`).
    Firewall,
    /// The firewall answers, but nothing blocks the addresses it lists.
    Rule,
    /// Bans are waiting because `max_bans_per_hour` has been reached.
    RateLimit,
    /// The firewall answers, but refuses to add a ban (for example because
    /// our account may read but not write). Only an accepted ban clears it.
    BanRefused,
    /// An address that has been banned for a while still reaches an NVR:
    /// the drop rule exists but does not block. Observed only when such an
    /// address reaches `maxretry` again; over once none has for
    /// `alert_after` in polls that read every NVR (see `Health::poll_ended`).
    Bypassed,
    /// An own address is in the address-list and hik-f2b could not remove
    /// it. Over once a look-up of every own address finds none listed.
    OwnListed,
    /// With a safe list: no enabled, valid rule accepts the safe list
    /// before the drop rule, so an own address that is banned is blocked.
    SafeRule,
    /// With a safe list: the firewall answers, but refuses to write the
    /// own address to it. Only a write that works ends it.
    SafeRefused,
}

impl Check {
    /// A stable identifier, used in log lines.
    pub fn key(&self) -> String {
        match self {
            Check::Nvr(name) => format!("nvr:{}", name),
            Check::Firewall => "firewall".to_string(),
            Check::Rule => "firewall-rule".to_string(),
            Check::RateLimit => "rate-limit".to_string(),
            Check::BanRefused => "ban-refused".to_string(),
            Check::Bypassed => "ban-bypassed".to_string(),
            Check::OwnListed => "own-address-listed".to_string(),
            Check::SafeRule => "safe-list-rule".to_string(),
            Check::SafeRefused => "safe-list-refused".to_string(),
        }
    }

    fn trouble(&self) -> String {
        match self {
            Check::Nvr(name) => format!("{} cannot be read", name),
            Check::Firewall => "the firewall is not usable".to_string(),
            Check::Rule => "banned addresses are not blocked".to_string(),
            Check::RateLimit => "new bans are held back by max_bans_per_hour".to_string(),
            Check::BanRefused => "the firewall refuses bans".to_string(),
            Check::Bypassed => "banned addresses still reach an NVR".to_string(),
            Check::OwnListed => {
                "an own address of hik-f2b is in the address-list and cannot be removed".to_string()
            }
            Check::SafeRule => {
                "the safe list does not keep the own address from being blocked".to_string()
            }
            Check::SafeRefused => {
                "the firewall refuses to write the own address to the safe list".to_string()
            }
        }
    }

    fn fixed(&self) -> String {
        match self {
            Check::Nvr(name) => format!("{} is readable again", name),
            Check::Firewall => "the firewall is usable again".to_string(),
            Check::Rule => "banned addresses are blocked again".to_string(),
            Check::RateLimit => "bans are no longer held back".to_string(),
            Check::BanRefused => "the firewall accepts bans again".to_string(),
            Check::Bypassed => "banned addresses no longer reach the NVRs".to_string(),
            Check::OwnListed => {
                "no own address of hik-f2b is in the address-list any more".to_string()
            }
            Check::SafeRule => {
                "the safe list keeps the own address from being blocked again".to_string()
            }
            Check::SafeRefused => {
                "the firewall writes the own address to the safe list again".to_string()
            }
        }
    }

    /// What is said when an alerted problem can no longer be observed.
    fn unknown(&self) -> String {
        match self {
            Check::BanRefused => BAN_REFUSED_UNKNOWN.to_string(),
            Check::Firewall => FIREWALL_UNKNOWN.to_string(),
            other => format!("{} can no longer be checked", other.key()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The problem has lasted `alert_after`.
    Alert,
    /// It still persists, `REMIND_EVERY` after the last alert or reminder.
    Reminder,
    /// An alerted problem went away.
    Recovered,
    /// An alerted problem can no longer be observed: neither its end nor
    /// its persistence can be shown, so it is no longer reminded of.
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    pub check: Check,
    pub kind: Kind,
    /// Seconds the problem had lasted when the notice was made.
    pub lasted: u64,
    /// The latest reason (empty for `Recovered`).
    pub reason: String,
}

impl Notice {
    /// The fixed English message text.
    pub fn text(&self) -> String {
        match self.kind {
            Kind::Alert | Kind::Reminder => format!(
                "\u{26a0}\u{fe0f} hik-f2b: {} for {}: {}",
                self.check.trouble(),
                fmt_duration(self.lasted),
                self.reason
            ),
            Kind::Recovered => format!(
                "\u{2705} hik-f2b: {} (after {})",
                self.check.fixed(),
                fmt_duration(self.lasted)
            ),
            Kind::Unknown => format!(
                "\u{2139}\u{fe0f} hik-f2b: {} (after {})",
                self.check.unknown(),
                fmt_duration(self.lasted)
            ),
        }
    }
}

struct Open {
    since: u64,
    reason: String,
    /// Host time of the last alert or reminder.
    alerted: Option<u64>,
}

pub struct Alerts {
    alert_after: u64,
    open: BTreeMap<Check, Open>,
    recovered: Vec<Notice>,
}

impl Alerts {
    pub fn new(alert_after: u64) -> Alerts {
        Alerts {
            alert_after,
            open: BTreeMap::new(),
            recovered: Vec::new(),
        }
    }

    /// `check` failed at `now`. The problem's start is kept if it is
    /// already open; the reason is updated.
    pub fn fail(&mut self, check: Check, reason: &str, now: u64) {
        let reason = clean_reason(reason);
        let open = self.open.entry(check).or_insert(Open {
            since: now,
            reason: String::new(),
            alerted: None,
        });
        open.reason = reason;
        // The host clock went back: count from now rather than waiting for
        // the clock to catch up.
        open.since = open.since.min(now);
    }

    /// `check` passed at `now`.
    pub fn pass(&mut self, check: &Check, now: u64) {
        if let Some(open) = self.open.remove(check) {
            if open.alerted.is_some() {
                self.recovered.push(Notice {
                    check: check.clone(),
                    kind: Kind::Recovered,
                    lasted: now.saturating_sub(open.since),
                    reason: String::new(),
                });
            }
        }
    }

    /// `check` can no longer be observed at `now`. The problem is closed
    /// without claiming a recovery: an alerted one gets one `Unknown`
    /// notice, one not yet alerted ends silently. The next `fail` opens it
    /// as a new problem.
    pub fn withdraw(&mut self, check: &Check, now: u64) {
        if let Some(open) = self.open.remove(check) {
            if open.alerted.is_some() {
                self.recovered.push(Notice {
                    check: check.clone(),
                    kind: Kind::Unknown,
                    lasted: now.saturating_sub(open.since),
                    reason: String::new(),
                });
            }
        }
    }

    /// The notices due at `now`: recoveries since the last call, then
    /// alerts and reminders.
    pub fn due(&mut self, now: u64) -> Vec<Notice> {
        let mut out = std::mem::take(&mut self.recovered);
        for (check, open) in self.open.iter_mut() {
            open.since = open.since.min(now);
            let lasted = now - open.since;
            let kind = match open.alerted {
                None if lasted >= self.alert_after => Kind::Alert,
                None => continue,
                Some(last) => {
                    // A last alert in the future can only come from the
                    // clock going back; restart the reminder period.
                    let last = last.min(now);
                    open.alerted = Some(last);
                    if now - last < REMIND_EVERY {
                        continue;
                    }
                    Kind::Reminder
                }
            };
            open.alerted = Some(now);
            out.push(Notice {
                check: check.clone(),
                kind,
                lasted,
                reason: open.reason.clone(),
            });
        }
        out
    }

    /// The keys of the problems that have been alerted and still persist.
    pub fn alerted(&self) -> Vec<String> {
        self.open
            .iter()
            .filter(|(_, o)| o.alerted.is_some())
            .map(|(c, _)| c.key())
            .collect()
    }
}

/// How the read of one NVR went in a poll.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvrRead<'a> {
    /// The NVR's log was read.
    Read,
    /// The NVR rejected our login (the error as the NVR client gives it).
    LoginRejected(&'a str),
    /// The NVR could not be reached or its log not read.
    Failed(&'a str),
    /// Not tried in this poll: the NVR is backing off after a rejected
    /// login, or the poll stopped before it. Its problem stays as it is.
    NotTried,
}

/// How one ban attempt on the firewall ended. Only attempts that ask the
/// firewall are reported: not those of a dry run or of notify-only mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BanAttempt<'a> {
    /// The firewall added the address.
    Accepted,
    /// The firewall already listed the address, within the grace period
    /// after its ban began or after the engine started: the failed logins
    /// may predate the ban.
    Listed,
    /// The firewall already listed the address, after both grace periods:
    /// a banned address still reached an NVR.
    Bypassed {
        ip: Ipv4Addr,
        /// The address-list, as the firewall describes it.
        list: &'a str,
        /// Host time the ban began, if known.
        banned_at: Option<u64>,
        /// The NVR it reached.
        nvr: &'a str,
    },
    /// The firewall refused to add this address.
    Refused { ip: Ipv4Addr, error: &'a str },
    /// The firewall could not be reached, refused our login or answered
    /// with an error; the ban loop ends here.
    Unreachable(&'a str),
}

/// An own address that is still in the address-list after hik-f2b tried
/// to remove it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OwnStuck<'a> {
    pub ip: Ipv4Addr,
    /// The address-list, as the firewall describes it.
    pub list: &'a str,
    /// Why the removal failed.
    pub error: &'a str,
}

/// How the write of the own address to the safe list ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SafeWrite<'a> {
    /// Every own address toward the router is in the safe list.
    Written,
    /// The firewall refused to write this one.
    Refused {
        ip: Ipv4Addr,
        /// The safe list's name.
        list: &'a str,
        error: &'a str,
    },
}

/// How the ban loop of a poll ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BansEnded {
    /// Every due ban was tried.
    Complete,
    /// `max_bans_per_hour` was reached with bans still due.
    RateLimited,
    /// The firewall was unreachable (`BanAttempt::Unreachable`).
    CutShort,
    /// The service is stopping.
    Stopped,
}

/// The health rules: which check opens, passes or is withdrawn when
/// something happens, on top of `Alerts`.
pub struct Health {
    alerts: Alerts,
    alert_after: u64,
    max_bans_per_hour: usize,
    /// Host time of the next periodic firewall check.
    next_check: u64,
    /// Whether the last ban loop was cut short by an unreachable firewall.
    cut_short: bool,
    /// Whether the open `Check::Firewall` problem is one that only writes
    /// show: a ban attempt found the firewall unusable, and neither a ban
    /// that the firewall answered nor a firewall check that failed came
    /// since. A firewall check that works does not end such a problem.
    write_failed: bool,
    /// Whether bans still waited at the end of the last ban loop.
    bans_wait: bool,
    /// Whether every NVR reported in this poll was read.
    all_read: bool,
    /// Host time a banned address was last seen reaching an NVR well after
    /// its ban (see `Check::Bypassed`); `None` once that problem is over.
    last_bypass: Option<u64>,
}

impl Health {
    pub fn new(alert_after: u64, max_bans_per_hour: usize) -> Health {
        Health {
            alerts: Alerts::new(alert_after),
            alert_after,
            max_bans_per_hour,
            next_check: 0,
            cut_short: false,
            write_failed: false,
            bans_wait: false,
            all_read: true,
            last_bypass: None,
        }
    }

    /// How the read of NVR `nvr` went at `now`. An NVR that is not read
    /// (for any reason) means the poll did not read every NVR.
    pub fn nvr_polled(&mut self, nvr: &str, read: NvrRead, now: u64) {
        let check = Check::Nvr(nvr.to_string());
        match read {
            NvrRead::Read => self.alerts.pass(&check, now),
            // The NVR is not polled while backing off, so the problem
            // stays open until the next attempt.
            NvrRead::LoginRejected(e) => {
                self.alerts
                    .fail(check, &format!("login rejected ({})", e), now)
            }
            NvrRead::Failed(e) => self.alerts.fail(check, e, now),
            NvrRead::NotTried => {}
        }
        if read != NvrRead::Read {
            self.all_read = false;
        }
    }

    /// How a firewall check round ended at `now`, at startup or periodic:
    /// in this order, the write of the safe list (if it ran to its end), the
    /// firewall check, the check of the safe list's rule (if it was made)
    /// and the look-up of the own addresses (if every one was asked).
    pub fn round_ended(&mut self, ended: &Ended, now: u64) {
        match &ended.safe {
            None => {}
            Some(SafeWritten::Written) => self.safe_written(SafeWrite::Written, now),
            Some(SafeWritten::Refused { ip, list, error }) => self.safe_written(
                SafeWrite::Refused {
                    ip: *ip,
                    list,
                    error,
                },
                now,
            ),
        }
        self.firewall_checked(&ended.firewall, now);
        if let Some(safe_rule) = &ended.safe_rule {
            self.safe_rule_checked(safe_rule, now);
        }
        match &ended.own {
            None => {}
            Some(OwnSwept::Clean) => self.own_swept(None, now),
            Some(OwnSwept::Stuck { ip, list, error }) => self.own_swept(
                Some(OwnStuck {
                    ip: *ip,
                    list,
                    error,
                }),
                now,
            ),
        }
    }

    /// The result of a firewall check at `now`, at startup or periodic. The
    /// next periodic check is due `HEALTH_CHECK_INTERVAL` later. A check
    /// that fails makes the firewall problem one that reads show too, so a
    /// later check that works may end it.
    fn firewall_checked(&mut self, result: &Result<String, HealthError>, now: u64) {
        self.next_check = now.saturating_add(HEALTH_CHECK_INTERVAL);
        match result {
            Ok(_) => {
                self.firewall_answered(now);
                self.alerts.pass(&Check::Rule, now);
            }
            Err(HealthError::Unusable(e)) => {
                self.write_failed = false;
                self.alerts.fail(Check::Firewall, e, now);
            }
            Err(HealthError::NotEnforced(e)) => {
                self.firewall_answered(now);
                self.alerts.fail(Check::Rule, e, now);
            }
        }
    }

    /// The firewall answered a check at `now`. That ends the firewall
    /// problem, unless only bans showed it: then a ban that waits will show
    /// whether bans work, and with none waiting that is not known, so the
    /// problem is withdrawn.
    fn firewall_answered(&mut self, now: u64) {
        if !self.write_failed {
            self.alerts.pass(&Check::Firewall, now);
        } else if !self.bans_wait {
            self.alerts.withdraw(&Check::Firewall, now);
            self.write_failed = false;
        }
    }

    /// Whether the periodic firewall check is due at `now`. It is skipped
    /// when the last ban loop found the firewall unusable: that is known, a
    /// second timeout would only delay the next poll, and a read that works
    /// must not end a problem that writes still show.
    pub fn check_due(&self, now: u64) -> bool {
        // A next check further away than the interval can only come from
        // the host clock having gone back.
        let due = now >= self.next_check || self.next_check - now > HEALTH_CHECK_INTERVAL;
        due && !self.cut_short
    }

    /// How one ban attempt ended at `now`. Every attempt but an unusable
    /// firewall shows that the firewall answers writes.
    pub fn ban_tried(&mut self, attempt: BanAttempt, now: u64) {
        self.write_failed = matches!(attempt, BanAttempt::Unreachable(_));
        match attempt {
            BanAttempt::Accepted | BanAttempt::Listed => {
                self.alerts.pass(&Check::Firewall, now);
                self.alerts.pass(&Check::BanRefused, now);
            }
            BanAttempt::Bypassed {
                ip,
                list,
                banned_at,
                nvr,
            } => {
                self.alerts.pass(&Check::Firewall, now);
                self.alerts.pass(&Check::BanRefused, now);
                let since = match banned_at {
                    Some(at) => format!(
                        "has been in {} for {}",
                        list,
                        fmt_duration(now.saturating_sub(at))
                    ),
                    None => format!("is in {}", list),
                };
                let reason = format!("{} {} and still reached {}", ip, since, nvr);
                self.alerts.fail(Check::Bypassed, &reason, now);
                self.last_bypass = Some(now);
            }
            // A successful read does not clear this: only a ban the
            // firewall accepts does. The firewall problem is left as it is:
            // the next check ends it, as the firewall answered this write.
            BanAttempt::Refused { ip, error } => {
                let reason = format!("{}: {}", ip, error);
                self.alerts.fail(Check::BanRefused, &reason, now);
            }
            // One problem, one alert: the periodic check would report the
            // same login or router trouble. A check that works does not
            // end it (see `firewall_answered`).
            BanAttempt::Unreachable(e) => self.alerts.fail(Check::Firewall, e, now),
        }
    }

    /// How the ban loop ended at `now`, and how many bans still wait.
    pub fn bans_ended(&mut self, end: BansEnded, waiting: usize, now: u64) {
        match end {
            BansEnded::RateLimited => {
                let reason = format!(
                    "{} address(es) waiting, limit {} per hour",
                    waiting, self.max_bans_per_hour
                );
                self.alerts.fail(Check::RateLimit, &reason, now);
            }
            BansEnded::Complete => self.alerts.pass(&Check::RateLimit, now),
            BansEnded::CutShort | BansEnded::Stopped => {}
        }
        if waiting == 0 {
            // Every refused ban expired or was dropped: nothing is left to
            // show whether the firewall would accept one now.
            self.alerts.withdraw(&Check::BanRefused, now);
        }
        self.cut_short = end == BansEnded::CutShort;
        self.bans_wait = waiting > 0;
    }

    /// Every own address that is worth asking was looked up in the
    /// address-list at `now`, and each one found was removed (`None`), or
    /// this one is still listed after its removal failed. Only a look-up
    /// that finds no own address left ends the problem.
    fn own_swept(&mut self, stuck: Option<OwnStuck>, now: u64) {
        match stuck {
            None => self.alerts.pass(&Check::OwnListed, now),
            Some(OwnStuck { ip, list, error }) => {
                let reason = format!(
                    "{} is in {}; remove it by hand and check that the router user may write: {}",
                    ip, list, error
                );
                self.alerts.fail(Check::OwnListed, &reason, now);
            }
        }
    }

    /// The result of the check of the safe list's rule at `now` (made with
    /// a firewall check that found the drop rule).
    fn safe_rule_checked(&mut self, result: &Result<String, String>, now: u64) {
        match result {
            Ok(_) => self.alerts.pass(&Check::SafeRule, now),
            Err(reason) => self.alerts.fail(Check::SafeRule, reason, now),
        }
    }

    /// How the write of the own address to the safe list ended at `now`.
    /// As for a ban, a refusal is a problem of its own, which only a write
    /// that works ends. (A firewall that cannot be used for the write is
    /// reported as a failed firewall check, see `round.rs`.)
    fn safe_written(&mut self, write: SafeWrite, now: u64) {
        match write {
            SafeWrite::Written => self.alerts.pass(&Check::SafeRefused, now),
            SafeWrite::Refused { ip, list, error } => {
                let reason = format!("{} cannot be written to {}: {}", ip, list, error);
                self.alerts.fail(Check::SafeRefused, &reason, now);
            }
        }
    }

    /// The end of a poll at `now`. Ends the `Check::Bypassed` problem once
    /// no banned address has reached an NVR for `alert_after`, counted only
    /// while every NVR is read (an NVR that cannot be read shows nothing
    /// either way). An attacker that pauses for less than that does not end
    /// it; so it is alerted when banned addresses keep reaching the NVRs for
    /// `alert_after` without such a pause.
    pub fn poll_ended(&mut self, now: u64) {
        let all_read = std::mem::replace(&mut self.all_read, true);
        let Some(last) = self.last_bypass else {
            return;
        };
        // A last time in the future can only come from the host clock
        // having gone back: count from now.
        let last = last.min(now);
        self.last_bypass = Some(last);
        if all_read && now - last >= self.alert_after {
            self.alerts.pass(&Check::Bypassed, now);
            self.last_bypass = None;
        }
    }

    /// The notices due at `now` (see `Alerts::due`).
    pub fn due(&mut self, now: u64) -> Vec<Notice> {
        self.alerts.due(now)
    }

    /// The keys of the problems that have been alerted and still persist.
    pub fn alerted(&self) -> Vec<String> {
        self.alerts.alerted()
    }
}

/// `10 min`, `5 h`, `3 d`.
pub fn fmt_duration(seconds: u64) -> String {
    if seconds < 7200 {
        format!("{} min", (seconds / 60).max(1))
    } else if seconds < 2 * 86400 {
        format!("{} h", seconds / 3600)
    } else {
        format!("{} d", seconds / 86400)
    }
}

/// A reason fit for a chat message: every URL (`scheme://...`, which names
/// a host, a port, a path and a query string) is replaced by `<url>`,
/// wherever it stands: after a space, in brackets or quotes, after `=`.
/// URLs are masked first, on the raw text. The rest is cut to `MAX_REASON`
/// characters with `util::printable`: control and invisible characters
/// become `?`, other Unicode stays (a path with Cyrillic letters is shown
/// as it is). That is safe because a reason goes only to the hik-f2b log
/// and to the Telegram message body, never to the router, an HTTP header
/// or the state file. An address with a port outside a URL
/// (`192.0.2.1:443` in a connection error) stays: it is the operator's own
/// device, and the chat is the operator's. The error strings this gets
/// never hold passwords or tokens: credentials travel in headers or form
/// bodies, which errors do not quote.
pub fn clean_reason(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        // the scheme: the letters, digits, `+`, `-` and `.` just before
        let start = rest[..at]
            .char_indices()
            .rev()
            .take_while(|(_, c)| c.is_ascii_alphanumeric() || "+-.".contains(*c))
            .last()
            .map_or(at, |(i, _)| i);
        let after = &rest[at + 3..];
        if start == at {
            out.push_str(&rest[..at + 3]);
            rest = after;
            continue;
        }
        out.push_str(&rest[..start]);
        // The URL ends at a space, a quote, a bracket that it did not open,
        // or the end; punctuation at its end belongs to the sentence.
        let mut end = after.len();
        let mut open = 0usize;
        for (i, c) in after.char_indices() {
            match c {
                '[' => open += 1,
                ']' if open > 0 => open -= 1,
                c if c.is_whitespace() || "\"'`<>(){}]".contains(c) => {
                    end = i;
                    break;
                }
                _ => {}
            }
        }
        let url = after[..end].trim_end_matches(|c| ".,;:!?".contains(c));
        out.push_str("<url>");
        rest = &after[url.len()..];
    }
    out.push_str(rest);
    util::printable(&out, MAX_REASON)
}

/// The result of one item of `--check`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Ok,
    Failed,
    /// Not configured; not a failure.
    Off,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckLine {
    pub item: String,
    pub status: Status,
    pub detail: String,
}

impl std::fmt::Display for CheckLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let status = match self.status {
            Status::Ok => "ok",
            Status::Failed => "FAILED",
            Status::Off => "off",
        };
        write!(f, "{:<8} {}: {}", status, self.item, self.detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AFTER: u64 = 600;
    const T0: u64 = 100_000_000;

    fn nvr(name: &str) -> Check {
        Check::Nvr(name.to_string())
    }

    fn kinds(notices: &[Notice]) -> Vec<(Check, Kind)> {
        notices.iter().map(|n| (n.check.clone(), n.kind)).collect()
    }

    #[test]
    fn not_before_alert_after_and_exactly_once() {
        let mut a = Alerts::new(AFTER);
        let mut sent = Vec::new();
        for t in (0..=3600).step_by(30) {
            a.fail(nvr("nvr2"), "HTTP 500", T0 + t);
            let due = a.due(T0 + t);
            if t < AFTER {
                assert!(due.is_empty(), "alert at {} s", t);
            }
            sent.extend(due);
        }
        assert_eq!(kinds(&sent), vec![(nvr("nvr2"), Kind::Alert)]);
        assert_eq!(sent[0].lasted, AFTER);
        assert_eq!(
            sent[0].text(),
            "\u{26a0}\u{fe0f} hik-f2b: nvr2 cannot be read for 10 min: HTTP 500"
        );
    }

    #[test]
    fn evaluated_even_without_a_new_observation() {
        // an NVR in auth backoff is not polled, but its problem persists
        let mut a = Alerts::new(AFTER);
        a.fail(nvr("nvr1"), "login rejected (HTTP 401)", T0);
        assert!(a.due(T0 + AFTER - 1).is_empty());
        assert_eq!(kinds(&a.due(T0 + AFTER)), vec![(nvr("nvr1"), Kind::Alert)]);
    }

    #[test]
    fn reminder_after_a_day_and_not_before() {
        let mut a = Alerts::new(AFTER);
        a.fail(Check::Rule, "no rule", T0);
        assert_eq!(a.due(T0 + AFTER).len(), 1);
        let alerted = T0 + AFTER;
        assert!(a.due(alerted + REMIND_EVERY - 1).is_empty());
        let reminder = a.due(alerted + REMIND_EVERY);
        assert_eq!(kinds(&reminder), vec![(Check::Rule, Kind::Reminder)]);
        assert_eq!(reminder[0].lasted, AFTER + REMIND_EVERY);
        assert!(reminder[0].text().contains("for 24 h: no rule"));
        assert!(a.due(alerted + 2 * REMIND_EVERY - 1).is_empty());
        assert_eq!(a.due(alerted + 2 * REMIND_EVERY).len(), 1);
    }

    #[test]
    fn recovery_only_if_alerted() {
        let mut a = Alerts::new(AFTER);
        a.fail(Check::Firewall, "timeout", T0);
        a.pass(&Check::Firewall, T0 + AFTER - 1);
        assert!(a.due(T0 + AFTER).is_empty());
        assert!(a.due(T0 + 10 * AFTER).is_empty());

        a.fail(Check::Firewall, "timeout", T0 + 20 * AFTER);
        assert_eq!(a.due(T0 + 21 * AFTER).len(), 1);
        a.pass(&Check::Firewall, T0 + 25 * AFTER);
        let back = a.due(T0 + 25 * AFTER);
        assert_eq!(kinds(&back), vec![(Check::Firewall, Kind::Recovered)]);
        assert_eq!(
            back[0].text(),
            "\u{2705} hik-f2b: the firewall is usable again (after 50 min)"
        );
        // passing again is not news
        a.pass(&Check::Firewall, T0 + 26 * AFTER);
        assert!(a.due(T0 + 26 * AFTER).is_empty());
        assert!(a.alerted().is_empty());
    }

    #[test]
    fn several_independent_problems() {
        let mut a = Alerts::new(AFTER);
        a.fail(nvr("nvr1"), "down", T0);
        a.fail(Check::RateLimit, "3 address(es) waiting", T0 + 300);
        a.fail(nvr("nvr2"), "down", T0 + 300);
        assert_eq!(kinds(&a.due(T0 + AFTER)), vec![(nvr("nvr1"), Kind::Alert)]);
        a.pass(&nvr("nvr2"), T0 + AFTER + 1); // never alerted: silent
        assert_eq!(
            kinds(&a.due(T0 + AFTER + 300)),
            vec![(Check::RateLimit, Kind::Alert)]
        );
        a.pass(&nvr("nvr1"), T0 + 2000);
        a.fail(Check::Rule, "none", T0 + 2000);
        assert_eq!(
            kinds(&a.due(T0 + 2000)),
            vec![(nvr("nvr1"), Kind::Recovered)]
        );
        assert_eq!(a.alerted(), vec!["rate-limit".to_string()]);
        assert_eq!(
            kinds(&a.due(T0 + 2000 + AFTER)),
            vec![(Check::Rule, Kind::Alert)]
        );
    }

    #[test]
    fn reason_is_updated_and_start_kept() {
        let mut a = Alerts::new(AFTER);
        a.fail(nvr("nvr1"), "first", T0);
        a.fail(nvr("nvr1"), "second", T0 + 300);
        let due = a.due(T0 + AFTER);
        assert_eq!(due[0].lasted, AFTER);
        assert_eq!(due[0].reason, "second");
    }

    #[test]
    fn clock_going_backwards_neither_panics_nor_spams() {
        let mut a = Alerts::new(AFTER);
        a.fail(nvr("nvr1"), "down", T0);
        assert_eq!(a.due(T0 + AFTER).len(), 1);
        // a year back
        let back = T0 + AFTER - 365 * 86400;
        a.fail(nvr("nvr1"), "down", back);
        for t in (0..REMIND_EVERY).step_by(600) {
            assert!(a.due(back + t).is_empty(), "spam at {}", t);
        }
        assert_eq!(a.due(back + REMIND_EVERY).len(), 1, "reminder resumes");
        a.pass(&nvr("nvr1"), 0);
        let rec = a.due(0);
        assert_eq!(kinds(&rec), vec![(nvr("nvr1"), Kind::Recovered)]);

        // a problem opened, then the clock goes back before it is alerted
        a.fail(Check::Firewall, "x", T0);
        assert!(a.due(T0 - 5000).is_empty());
        assert!(a.due(T0 - 5000 + AFTER - 1).is_empty());
        assert_eq!(a.due(T0 - 5000 + AFTER).len(), 1);
        // and extreme values
        a.fail(Check::Rule, "x", u64::MAX);
        a.due(u64::MAX);
        a.due(0);
        a.pass(&Check::Rule, 0);
    }

    #[test]
    fn durations() {
        assert_eq!(fmt_duration(0), "1 min");
        assert_eq!(fmt_duration(600), "10 min");
        assert_eq!(fmt_duration(7199), "119 min");
        assert_eq!(fmt_duration(86400), "24 h");
        assert_eq!(fmt_duration(3 * 86400), "3 d");
        assert_eq!(fmt_duration(u64::MAX), format!("{} d", u64::MAX / 86400));
    }

    #[test]
    fn reasons_are_cleaned() {
        assert_eq!(
            clean_reason(
                "http://192.0.2.1:8080/rest/ip/firewall/raw?src-address-list=x: Connection Failed: refused"
            ),
            "<url>: Connection Failed: refused"
        );
        assert_eq!(clean_reason("a\nb\u{442}"), "a?b\u{442}");
        assert_eq!(clean_reason("a\u{202e}b\u{200b}c\u{2028}d"), "a?b?c?d");
        assert_eq!(
            clean_reason("cannot read /var/lib/hik-f2b/стан.txt: denied"),
            "cannot read /var/lib/hik-f2b/стан.txt: denied"
        );
        assert_eq!(
            clean_reason("see https://192.0.2.1/шлях?x=1 for /etc/конфіг"),
            "see <url> for /etc/конфіг"
        );
        assert_eq!(clean_reason(&"x".repeat(500)).len(), MAX_REASON);
        assert_eq!(clean_reason(&"ж".repeat(500)).chars().count(), MAX_REASON);
        let mut a = Alerts::new(AFTER);
        a.fail(Check::Firewall, "see https://192.0.2.1/x now", T0);
        assert_eq!(a.due(T0 + AFTER)[0].reason, "see <url> now");
    }

    #[test]
    fn urls_are_masked_wherever_they_stand() {
        for (text, clean) in [
            ("https://192.0.2.1/x", "<url>"),
            ("(https://192.0.2.1/rest?x=1)", "(<url>)"),
            ("[http://192.0.2.1:80/a]", "[<url>]"),
            ("\"https://192.0.2.1/a\" failed", "\"<url>\" failed"),
            ("'http://192.0.2.1/a'", "'<url>'"),
            ("url=https://192.0.2.1/a?token=x, retry", "url=<url>, retry"),
            ("<https://192.0.2.1/a>", "<<url>>"),
            ("see http://[2001:db8::1]:8080/ISAPI/x.", "see <url>."),
            (
                "at HTTPS://Router.Example.Net:8443/rest: refused",
                "at <url>: refused",
            ),
            (
                "two: http://192.0.2.1/a http://192.0.2.2/b",
                "two: <url> <url>",
            ),
            ("glued:http://192.0.2.1/a", "glued:<url>"),
            ("ftp://192.0.2.1/x", "<url>"),
            ("Network Error:\thttp://192.0.2.1/x", "Network Error:?<url>"),
            // not URLs: kept as they are
            ("://nothing", "://nothing"),
            (
                "connect to 192.0.2.1:8443 refused",
                "connect to 192.0.2.1:8443 refused",
            ),
            ("HTTP 401: Unauthorized", "HTTP 401: Unauthorized"),
        ] {
            assert_eq!(clean_reason(text), clean, "{:?}", text);
        }
    }

    #[test]
    fn keys_are_stable() {
        assert_eq!(nvr("nvr2").key(), "nvr:nvr2");
        assert_eq!(Check::Firewall.key(), "firewall");
        assert_eq!(Check::Rule.key(), "firewall-rule");
        assert_eq!(Check::RateLimit.key(), "rate-limit");
        assert_eq!(Check::BanRefused.key(), "ban-refused");
        assert_eq!(Check::Bypassed.key(), "ban-bypassed");
        assert_eq!(Check::OwnListed.key(), "own-address-listed");
        assert_eq!(Check::SafeRule.key(), "safe-list-rule");
        assert_eq!(Check::SafeRefused.key(), "safe-list-refused");
    }

    #[test]
    fn withdrawn_problem_is_neither_reminded_nor_recovered() {
        let mut a = Alerts::new(AFTER);
        // not yet alerted: ends silently
        a.fail(Check::BanRefused, "HTTP 400", T0);
        a.withdraw(&Check::BanRefused, T0 + 60);
        assert!(a.due(T0 + AFTER).is_empty());

        // alerted: one notice that says the outcome is unknown
        a.fail(Check::BanRefused, "HTTP 400", T0 + AFTER);
        assert_eq!(a.due(T0 + 2 * AFTER).len(), 1);
        a.withdraw(&Check::BanRefused, T0 + 3 * AFTER);
        let notices = a.due(T0 + 3 * AFTER);
        assert_eq!(kinds(&notices), vec![(Check::BanRefused, Kind::Unknown)]);
        assert_eq!(
            notices[0].text(),
            "\u{2139}\u{fe0f} hik-f2b: no refused ban is waiting any more; whether the \
             firewall accepts bans is not known until the next ban (after 20 min)"
        );
        assert!(a.alerted().is_empty());
        // no reminder, and a pass is not news either
        assert!(a.due(T0 + 3 * AFTER + 2 * REMIND_EVERY).is_empty());
        a.pass(&Check::BanRefused, T0 + 4 * AFTER);
        assert!(a.due(T0 + 4 * AFTER).is_empty());
        // withdrawing what is not open does nothing
        a.withdraw(&Check::Firewall, T0);
        assert!(a.due(T0 + 5 * AFTER).is_empty());
    }

    // The rules of `Health`: which check a report opens, passes or
    // withdraws. Each test reports what the engine would and looks at the
    // notices that `alert_after` later brings.

    const LIMIT: usize = 20;
    const IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

    fn health() -> Health {
        Health::new(AFTER, LIMIT)
    }

    /// The problems that are open at `now`: they are alerted `AFTER` later.
    /// Alerts every open problem, so call it once per test step.
    fn open_at(h: &mut Health, now: u64) -> Vec<Check> {
        h.due(now + AFTER)
            .into_iter()
            .filter(|n| n.kind == Kind::Alert)
            .map(|n| n.check)
            .collect()
    }

    fn reasons(notices: &[Notice]) -> Vec<(Check, String)> {
        notices
            .iter()
            .map(|n| (n.check.clone(), n.reason.clone()))
            .collect()
    }

    #[test]
    fn nvr_reads_open_and_end_the_nvr_check() {
        let mut h = health();
        h.nvr_polled("nvr1", NvrRead::LoginRejected("HTTP 401"), T0);
        h.nvr_polled("nvr2", NvrRead::Failed("timed out"), T0);
        h.nvr_polled("nvr3", NvrRead::Read, T0);
        let due = h.due(T0 + AFTER);
        assert_eq!(
            reasons(&due),
            vec![
                (nvr("nvr1"), "login rejected (HTTP 401)".to_string()),
                (nvr("nvr2"), "timed out".to_string()),
            ]
        );
        // backing off: not tried, the problem stays open and is not news
        h.nvr_polled("nvr1", NvrRead::NotTried, T0 + AFTER + 30);
        assert!(h.due(T0 + AFTER + 30).is_empty());
        assert_eq!(h.alerted(), vec!["nvr:nvr1", "nvr:nvr2"]);
        // a read ends it
        h.nvr_polled("nvr1", NvrRead::Read, T0 + 2 * AFTER);
        h.nvr_polled("nvr2", NvrRead::Read, T0 + 2 * AFTER);
        assert_eq!(
            kinds(&h.due(T0 + 2 * AFTER)),
            vec![
                (nvr("nvr1"), Kind::Recovered),
                (nvr("nvr2"), Kind::Recovered)
            ]
        );
    }

    #[test]
    fn not_tried_does_not_open_a_problem() {
        let mut h = health();
        h.nvr_polled("nvr1", NvrRead::NotTried, T0);
        assert!(open_at(&mut h, T0).is_empty());
    }

    #[test]
    fn firewall_check_results() {
        // usable: both the firewall and the rule pass
        let mut h = health();
        h.firewall_checked(&Err(HealthError::Unusable("timeout".into())), T0);
        h.firewall_checked(&Err(HealthError::NotEnforced("no rule".into())), T0);
        assert_eq!(open_at(&mut h, T0), vec![Check::Rule]);
        h.firewall_checked(&Ok("rule found".into()), T0 + AFTER);
        assert_eq!(
            kinds(&h.due(T0 + AFTER)),
            vec![(Check::Rule, Kind::Recovered)]
        );

        // unusable: says nothing about the rule
        let mut h = health();
        h.firewall_checked(&Err(HealthError::NotEnforced("no rule".into())), T0);
        h.firewall_checked(&Err(HealthError::Unusable("timeout".into())), T0);
        let due = h.due(T0 + AFTER);
        assert_eq!(
            reasons(&due),
            vec![
                (Check::Firewall, "timeout".to_string()),
                (Check::Rule, "no rule".to_string()),
            ]
        );

        // rule missing or wrong: the firewall itself is usable
        let mut h = health();
        h.firewall_checked(&Err(HealthError::Unusable("timeout".into())), T0);
        assert_eq!(h.due(T0 + AFTER).len(), 1);
        h.firewall_checked(
            &Err(HealthError::NotEnforced("rule disabled".into())),
            T0 + AFTER,
        );
        assert_eq!(
            kinds(&h.due(T0 + AFTER)),
            vec![(Check::Firewall, Kind::Recovered)]
        );
        assert_eq!(
            reasons(&h.due(T0 + 2 * AFTER)),
            vec![(Check::Rule, "rule disabled".to_string())]
        );
    }

    #[test]
    fn periodic_check_every_interval() {
        let mut h = health();
        // never checked: due at once
        assert!(h.check_due(T0));
        h.firewall_checked(&Ok(String::new()), T0);
        assert!(!h.check_due(T0));
        assert!(!h.check_due(T0 + HEALTH_CHECK_INTERVAL - 1));
        assert!(h.check_due(T0 + HEALTH_CHECK_INTERVAL));
        // a failed check counts as a check
        h.firewall_checked(&Err(HealthError::Unusable("x".into())), T0 + 1000);
        assert!(!h.check_due(T0 + 1000 + HEALTH_CHECK_INTERVAL - 1));
        assert!(h.check_due(T0 + 1000 + HEALTH_CHECK_INTERVAL));
    }

    #[test]
    fn periodic_check_after_the_host_clock_went_back() {
        let mut h = health();
        h.firewall_checked(&Ok(String::new()), T0);
        // the next check is at most one interval away
        assert!(!h.check_due(T0 + HEALTH_CHECK_INTERVAL - 1));
        assert!(!h.check_due(T0));
        assert!(h.check_due(T0 - 1));
        assert!(h.check_due(T0 - 86400));
    }

    #[test]
    fn periodic_check_skipped_after_the_ban_loop_was_cut_short() {
        // A read that works must not end a problem that writes still show.
        let mut h = health();
        h.ban_tried(BanAttempt::Unreachable("cannot reach the firewall"), T0);
        h.bans_ended(BansEnded::CutShort, 3, T0);
        assert!(!h.check_due(T0));
        assert!(!h.check_due(T0 + 10 * HEALTH_CHECK_INTERVAL));
        // the next ban loop that is not cut short lets it run again
        for end in [
            BansEnded::Complete,
            BansEnded::RateLimited,
            BansEnded::Stopped,
        ] {
            h.bans_ended(BansEnded::CutShort, 3, T0);
            assert!(!h.check_due(T0 + 1000));
            h.bans_ended(end, 3, T0 + 1000);
            assert!(h.check_due(T0 + 1000), "{:?}", end);
        }
        assert_eq!(
            reasons(&h.due(T0 + 1000 + AFTER)),
            vec![
                (Check::Firewall, "cannot reach the firewall".to_string()),
                (
                    Check::RateLimit,
                    "3 address(es) waiting, limit 20 per hour".to_string()
                ),
            ]
        );
    }

    #[test]
    fn accepted_or_listed_ban_passes_firewall_and_ban_refused() {
        for attempt in [BanAttempt::Accepted, BanAttempt::Listed] {
            let mut h = health();
            h.ban_tried(BanAttempt::Unreachable("timeout"), T0);
            h.ban_tried(
                BanAttempt::Refused {
                    ip: IP,
                    error: "HTTP 400",
                },
                T0,
            );
            assert_eq!(h.due(T0 + AFTER).len(), 2);
            h.ban_tried(attempt, T0 + AFTER + 60);
            assert_eq!(
                kinds(&h.due(T0 + AFTER + 60)),
                vec![
                    (Check::Firewall, Kind::Recovered),
                    (Check::BanRefused, Kind::Recovered)
                ],
                "{:?}",
                attempt
            );
            // and opens nothing
            assert!(h.alerted().is_empty());
            assert!(open_at(&mut h, T0 + AFTER + 60).is_empty());
        }
    }

    #[test]
    fn refused_ban_is_ended_only_by_an_accepted_ban() {
        let mut h = health();
        h.ban_tried(
            BanAttempt::Refused {
                ip: IP,
                error: "HTTP 400: not allowed",
            },
            T0,
        );
        let due = h.due(T0 + AFTER);
        assert_eq!(
            reasons(&due),
            vec![(
                Check::BanRefused,
                "198.51.100.7: HTTP 400: not allowed".to_string()
            )]
        );
        assert_eq!(
            due[0].text(),
            "\u{26a0}\u{fe0f} hik-f2b: the firewall refuses bans for 10 min: \
             198.51.100.7: HTTP 400: not allowed"
        );
        // a successful read, a complete ban loop with bans still waiting, a
        // poll: none of these end it
        h.firewall_checked(&Ok(String::new()), T0 + AFTER);
        h.bans_ended(BansEnded::Complete, 1, T0 + AFTER);
        h.poll_ended(T0 + AFTER);
        assert!(h.due(T0 + AFTER).is_empty());
        assert_eq!(h.alerted(), vec!["ban-refused"]);
        h.ban_tried(BanAttempt::Accepted, T0 + 2 * AFTER);
        assert_eq!(
            kinds(&h.due(T0 + 2 * AFTER)),
            vec![(Check::BanRefused, Kind::Recovered)]
        );
    }

    #[test]
    fn refused_ban_is_withdrawn_when_no_ban_waits() {
        for end in [
            BansEnded::Complete,
            BansEnded::RateLimited,
            BansEnded::CutShort,
            BansEnded::Stopped,
        ] {
            let mut h = health();
            h.ban_tried(
                BanAttempt::Refused {
                    ip: IP,
                    error: "HTTP 400",
                },
                T0,
            );
            assert_eq!(h.due(T0 + AFTER).len(), 1);
            h.bans_ended(end, 1, T0 + AFTER);
            assert!(h.due(T0 + AFTER).is_empty());
            h.bans_ended(end, 0, T0 + 2 * AFTER);
            let notices = h.due(T0 + 2 * AFTER);
            let refused: Vec<_> = kinds(&notices)
                .into_iter()
                .filter(|(c, _)| *c == Check::BanRefused)
                .collect();
            assert_eq!(
                refused,
                vec![(Check::BanRefused, Kind::Unknown)],
                "{:?}",
                end
            );
            assert!(!h.alerted().contains(&"ban-refused".to_string()));
        }
        // not yet alerted: withdrawn silently
        let mut h = health();
        h.ban_tried(
            BanAttempt::Refused {
                ip: IP,
                error: "HTTP 400",
            },
            T0,
        );
        h.bans_ended(BansEnded::Complete, 0, T0);
        assert!(open_at(&mut h, T0).is_empty());
    }

    #[test]
    fn unreachable_firewall_during_bans_is_one_firewall_problem() {
        let mut h = health();
        h.ban_tried(
            BanAttempt::Unreachable("cannot reach the firewall: timed out"),
            T0,
        );
        h.bans_ended(BansEnded::CutShort, 2, T0);
        // the same trouble, reported again by later loops: still one alert
        h.ban_tried(
            BanAttempt::Unreachable("the firewall refuses our login: HTTP 401"),
            T0 + 300,
        );
        h.bans_ended(BansEnded::CutShort, 2, T0 + 300);
        let due = h.due(T0 + AFTER);
        assert_eq!(
            reasons(&due),
            vec![(
                Check::Firewall,
                "the firewall refuses our login: HTTP 401".to_string()
            )]
        );
        assert_eq!(due[0].lasted, AFTER);
        assert!(h.due(T0 + 2 * AFTER).is_empty());
    }

    /// Bans got HTTP 5xx while reads work: the problem is one that only
    /// writes show. A ban loop that found the firewall unusable, alerted.
    fn writes_failed(h: &mut Health, now: u64) {
        h.ban_tried(
            BanAttempt::Unreachable("the firewall answers with an error: HTTP 500"),
            now,
        );
        h.bans_ended(BansEnded::CutShort, 2, now);
        assert_eq!(
            kinds(&h.due(now + AFTER)),
            vec![(Check::Firewall, Kind::Alert)]
        );
    }

    #[test]
    fn a_read_check_that_works_withdraws_a_write_problem_once_no_ban_waits() {
        let mut h = health();
        writes_failed(&mut h, T0);
        // every waiting ban expired: the loop ends complete, the read check
        // runs and works
        let now = T0 + 2 * AFTER;
        h.bans_ended(BansEnded::Complete, 0, now);
        assert!(h.check_due(now));
        h.firewall_checked(&Ok("rule found".into()), now);
        let notices = h.due(now);
        assert_eq!(kinds(&notices), vec![(Check::Firewall, Kind::Unknown)]);
        assert_eq!(
            notices[0].text(),
            "\u{2139}\u{fe0f} hik-f2b: the firewall answers the check, but the last ban \
             failed and no ban is waiting any more; whether the firewall accepts bans is not \
             known until the next ban (after 20 min)"
        );
        assert!(h.alerted().is_empty());
        // no reminder, and later read checks are not news
        h.firewall_checked(&Ok(String::new()), now + HEALTH_CHECK_INTERVAL);
        assert!(h.due(now + 2 * REMIND_EVERY).is_empty());
        // the next ban that fails is a new problem, the next one accepted
        // is not news
        h.ban_tried(BanAttempt::Accepted, now + 3 * REMIND_EVERY);
        assert!(h.due(now + 3 * REMIND_EVERY).is_empty());
        writes_failed(&mut h, now + 4 * REMIND_EVERY);
    }

    #[test]
    fn a_write_problem_not_yet_alerted_is_withdrawn_silently() {
        let mut h = health();
        h.ban_tried(BanAttempt::Unreachable("HTTP 500"), T0);
        h.bans_ended(BansEnded::CutShort, 1, T0);
        h.bans_ended(BansEnded::Complete, 0, T0 + 60);
        h.firewall_checked(&Ok(String::new()), T0 + 60);
        assert!(open_at(&mut h, T0 + 60).is_empty());
        assert!(h.due(T0 + 2 * REMIND_EVERY).is_empty());
    }

    #[test]
    fn a_read_check_that_works_leaves_a_write_problem_open_while_bans_wait() {
        let mut h = health();
        writes_failed(&mut h, T0);
        // the loop did not try: rate limited, then stopped
        for (end, at) in [(BansEnded::RateLimited, 1), (BansEnded::Stopped, 2)] {
            let now = T0 + AFTER + at * HEALTH_CHECK_INTERVAL;
            h.bans_ended(end, 2, now);
            h.firewall_checked(&Ok(String::new()), now);
            let firewall: Vec<_> = kinds(&h.due(now))
                .into_iter()
                .filter(|(c, _)| *c == Check::Firewall)
                .collect();
            assert!(firewall.is_empty(), "{:?}: {:?}", end, firewall);
            assert!(h.alerted().contains(&"firewall".to_string()), "{:?}", end);
        }
        // the next attempt shows: accepted, the problem is over
        let now = T0 + 2 * AFTER;
        h.ban_tried(BanAttempt::Accepted, now);
        h.bans_ended(BansEnded::Complete, 0, now);
        assert_eq!(kinds(&h.due(now)), vec![(Check::Firewall, Kind::Recovered)]);
        assert!(h.alerted().is_empty());
    }

    #[test]
    fn a_read_check_that_finds_no_rule_does_not_end_a_write_problem_either() {
        // the router answers the check: as for a check that works, only
        // the rule is news
        let mut h = health();
        writes_failed(&mut h, T0);
        let now = T0 + 2 * AFTER;
        h.bans_ended(BansEnded::RateLimited, 2, now);
        h.firewall_checked(&Err(HealthError::NotEnforced("no rule".into())), now);
        assert!(h.due(now).is_empty());
        assert_eq!(h.alerted(), vec!["firewall"]);
        h.bans_ended(BansEnded::Complete, 0, now + 60);
        h.firewall_checked(&Err(HealthError::NotEnforced("no rule".into())), now + 60);
        assert_eq!(
            kinds(&h.due(now + 60)),
            vec![(Check::Firewall, Kind::Unknown)]
        );
        assert_eq!(
            reasons(&h.due(now + AFTER)),
            vec![(Check::Rule, "no rule".to_string())]
        );
    }

    #[test]
    fn a_ban_that_the_firewall_answers_ends_a_write_problem() {
        for attempt in [BanAttempt::Accepted, BanAttempt::Listed] {
            let mut h = health();
            writes_failed(&mut h, T0);
            h.ban_tried(attempt, T0 + 2 * AFTER);
            assert_eq!(
                kinds(&h.due(T0 + 2 * AFTER)),
                vec![(Check::Firewall, Kind::Recovered)],
                "{:?}",
                attempt
            );
            // and the read checks after it are not news
            h.bans_ended(BansEnded::Complete, 0, T0 + 2 * AFTER);
            h.firewall_checked(&Ok(String::new()), T0 + 2 * AFTER);
            assert!(h.due(T0 + 3 * AFTER).is_empty(), "{:?}", attempt);
        }
        let mut h = health();
        writes_failed(&mut h, T0);
        bypass(&mut h, None, T0 + 2 * AFTER);
        assert_eq!(
            kinds(&h.due(T0 + 2 * AFTER)),
            vec![(Check::Firewall, Kind::Recovered)]
        );
    }

    #[test]
    fn a_read_check_that_fails_lets_a_later_one_end_a_write_problem() {
        // an unreachable router: the bans fail, expire, the read check
        // fails too; then the router is back
        let mut h = health();
        h.ban_tried(BanAttempt::Unreachable("cannot reach the firewall"), T0);
        h.bans_ended(BansEnded::CutShort, 1, T0);
        assert_eq!(h.due(T0 + AFTER).len(), 1);
        let now = T0 + 2 * AFTER;
        h.bans_ended(BansEnded::Complete, 0, now);
        h.firewall_checked(&Err(HealthError::Unusable("timed out".into())), now);
        assert!(h.due(now).is_empty());
        assert_eq!(h.alerted(), vec!["firewall"]);
        let back = now + HEALTH_CHECK_INTERVAL;
        h.bans_ended(BansEnded::Complete, 0, back);
        h.firewall_checked(&Ok(String::new()), back);
        let notices = h.due(back);
        assert_eq!(kinds(&notices), vec![(Check::Firewall, Kind::Recovered)]);
        assert_eq!(
            notices[0].text(),
            "\u{2705} hik-f2b: the firewall is usable again (after 25 min)"
        );
    }

    #[test]
    fn a_refused_ban_ends_what_only_writes_showed() {
        // the router answered the write about the address: the next read
        // check that works ends the firewall problem, as before; the
        // refusal is its own problem
        let mut h = health();
        writes_failed(&mut h, T0);
        let now = T0 + 2 * AFTER;
        h.ban_tried(
            BanAttempt::Refused {
                ip: IP,
                error: "HTTP 400",
            },
            now,
        );
        h.bans_ended(BansEnded::Complete, 1, now);
        assert!(h.due(now).is_empty());
        h.firewall_checked(&Ok(String::new()), now + 60);
        assert_eq!(
            kinds(&h.due(now + 60)),
            vec![(Check::Firewall, Kind::Recovered)]
        );
        assert_eq!(h.alerted(), Vec::<String>::new());
        assert_eq!(open_at(&mut h, now + 60), vec![Check::BanRefused]);
    }

    #[test]
    fn rate_limit_passes_only_after_a_complete_ban_loop() {
        let mut h = health();
        h.bans_ended(BansEnded::RateLimited, 5, T0);
        let due = h.due(T0 + AFTER);
        assert_eq!(
            due[0].text(),
            "\u{26a0}\u{fe0f} hik-f2b: new bans are held back by max_bans_per_hour for \
             10 min: 5 address(es) waiting, limit 20 per hour"
        );
        // cut short by an unreachable firewall, or stopped: not known
        h.bans_ended(BansEnded::CutShort, 5, T0 + AFTER + 30);
        h.bans_ended(BansEnded::Stopped, 5, T0 + AFTER + 60);
        assert!(h.due(T0 + AFTER + 60).is_empty());
        assert_eq!(h.alerted(), vec!["rate-limit"]);
        h.bans_ended(BansEnded::Complete, 0, T0 + 2 * AFTER);
        assert_eq!(
            kinds(&h.due(T0 + 2 * AFTER)),
            vec![(Check::RateLimit, Kind::Recovered)]
        );
        // the reason gives the bans that wait now and the limit
        let mut h = Health::new(AFTER, 3);
        h.bans_ended(BansEnded::RateLimited, 1, T0);
        h.bans_ended(BansEnded::RateLimited, 7, T0 + 60);
        assert_eq!(
            reasons(&h.due(T0 + AFTER)),
            vec![(
                Check::RateLimit,
                "7 address(es) waiting, limit 3 per hour".to_string()
            )]
        );
    }

    fn bypass(h: &mut Health, banned_at: Option<u64>, now: u64) {
        h.ban_tried(
            BanAttempt::Bypassed {
                ip: IP,
                list: "cctv_ban on router",
                banned_at,
                nvr: "nvr1",
            },
            now,
        );
    }

    #[test]
    fn bypassed_reason_and_what_else_it_passes() {
        let mut h = health();
        h.ban_tried(BanAttempt::Unreachable("timeout"), T0 - 2 * AFTER);
        assert_eq!(h.due(T0 - AFTER).len(), 1);
        bypass(&mut h, Some(T0 - 3 * 3600), T0);
        bypass(&mut h, None, T0 + 60);
        let due = h.due(T0 + 60);
        assert_eq!(kinds(&due), vec![(Check::Firewall, Kind::Recovered)]);
        let due = h.due(T0 + AFTER);
        assert_eq!(
            reasons(&due),
            vec![(
                Check::Bypassed,
                "198.51.100.7 is in cctv_ban on router and still reached nvr1".to_string()
            )]
        );
        let mut h = health();
        bypass(&mut h, Some(T0 - 3 * 3600), T0);
        assert_eq!(
            h.due(T0 + AFTER)[0].text(),
            "\u{26a0}\u{fe0f} hik-f2b: banned addresses still reach an NVR for 10 min: \
             198.51.100.7 has been in cctv_ban on router for 3 h and still reached nvr1"
        );
        // an address listed within the grace period opens nothing
        let mut h = health();
        h.ban_tried(BanAttempt::Listed, T0);
        h.poll_ended(T0);
        assert!(open_at(&mut h, T0).is_empty());
    }

    #[test]
    fn bypass_ends_after_alert_after_in_a_poll_that_read_every_nvr() {
        let mut h = health();
        bypass(&mut h, None, T0);
        h.poll_ended(T0);
        h.nvr_polled("nvr1", NvrRead::Read, T0 + AFTER - 1);
        h.poll_ended(T0 + AFTER - 1);
        let due = h.due(T0 + AFTER - 1);
        assert!(due.is_empty());
        // alerted: the problem lasted alert_after without a pause that long
        h.nvr_polled("nvr1", NvrRead::Read, T0 + AFTER);
        let due = h.due(T0 + AFTER);
        assert_eq!(kinds(&due), vec![(Check::Bypassed, Kind::Alert)]);
        // the end is decided at the end of the poll
        assert!(h.due(T0 + AFTER).is_empty());
        h.poll_ended(T0 + AFTER);
        assert_eq!(
            kinds(&h.due(T0 + AFTER)),
            vec![(Check::Bypassed, Kind::Recovered)]
        );
        // over: later polls say nothing
        h.poll_ended(T0 + 10 * AFTER);
        assert!(h.due(T0 + 10 * AFTER).is_empty());
    }

    #[test]
    fn bypass_does_not_end_in_a_poll_that_missed_an_nvr() {
        for missed in [
            NvrRead::Failed("timed out"),
            NvrRead::LoginRejected("HTTP 401"),
            NvrRead::NotTried,
        ] {
            let mut h = health();
            bypass(&mut h, None, T0);
            h.poll_ended(T0);
            assert_eq!(h.due(T0 + AFTER).len(), 1);
            h.nvr_polled("nvr1", NvrRead::Read, T0 + 2 * AFTER);
            h.nvr_polled("nvr2", missed, T0 + 2 * AFTER);
            h.poll_ended(T0 + 2 * AFTER);
            assert_eq!(h.alerted(), vec!["ban-bypassed"], "{:?}", missed);
            // only that poll: the next one that reads every NVR ends it
            h.nvr_polled("nvr1", NvrRead::Read, T0 + 3 * AFTER);
            h.nvr_polled("nvr2", NvrRead::Read, T0 + 3 * AFTER);
            h.poll_ended(T0 + 3 * AFTER);
            let due = h.due(T0 + 3 * AFTER);
            assert!(
                due.iter()
                    .any(|n| n.check == Check::Bypassed && n.kind == Kind::Recovered),
                "{:?}",
                missed
            );
        }
    }

    #[test]
    fn a_new_bypass_restarts_the_timer() {
        let mut h = health();
        bypass(&mut h, None, T0);
        h.poll_ended(T0);
        bypass(&mut h, None, T0 + AFTER - 1);
        h.poll_ended(T0 + AFTER - 1);
        h.poll_ended(T0 + AFTER);
        h.poll_ended(T0 + 2 * AFTER - 2);
        assert_eq!(h.alerted(), Vec::<String>::new());
        assert_eq!(
            kinds(&h.due(T0 + 2 * AFTER - 2)),
            vec![(Check::Bypassed, Kind::Alert)]
        );
        h.poll_ended(T0 + 2 * AFTER - 1);
        assert_eq!(
            kinds(&h.due(T0 + 2 * AFTER - 1)),
            vec![(Check::Bypassed, Kind::Recovered)]
        );
    }

    #[test]
    fn bypass_timer_after_the_host_clock_went_back() {
        let mut h = health();
        bypass(&mut h, None, T0);
        h.poll_ended(T0);
        // a day back: counted from then, neither ended at once nor never
        let back = T0 - 86400;
        h.poll_ended(back);
        assert!(h.due(back).is_empty());
        h.poll_ended(back + AFTER - 1);
        assert_eq!(
            kinds(&h.due(back + AFTER)),
            vec![(Check::Bypassed, Kind::Alert)]
        );
        h.poll_ended(back + AFTER);
        assert_eq!(
            kinds(&h.due(back + AFTER)),
            vec![(Check::Bypassed, Kind::Recovered)]
        );
    }

    #[test]
    fn an_own_address_that_cannot_be_removed_until_none_is_listed() {
        let stuck = OwnStuck {
            ip: Ipv4Addr::new(192, 0, 2, 200),
            list: "MikroTik address-list cctv_ban",
            error: "refused: HTTP 400",
        };
        let mut h = health();
        h.own_swept(Some(stuck), T0);
        let due = h.due(T0 + AFTER);
        assert_eq!(kinds(&due), vec![(Check::OwnListed, Kind::Alert)]);
        assert_eq!(
            due[0].text(),
            "\u{26a0}\u{fe0f} hik-f2b: an own address of hik-f2b is in the address-list and \
             cannot be removed for 10 min: 192.0.2.200 is in MikroTik address-list cctv_ban; \
             remove it by hand and check that the router user may write: refused: HTTP 400"
        );
        // nothing else ends it: a firewall check, a ban, a poll
        h.firewall_checked(&Ok(String::new()), T0 + AFTER);
        h.ban_tried(BanAttempt::Accepted, T0 + AFTER);
        h.bans_ended(BansEnded::Complete, 0, T0 + AFTER);
        h.poll_ended(T0 + AFTER);
        assert!(h.due(T0 + AFTER).is_empty());
        assert_eq!(h.alerted(), vec!["own-address-listed"]);
        // still stuck: no news until the reminder
        h.own_swept(Some(stuck), T0 + 2 * AFTER);
        assert!(h.due(T0 + 2 * AFTER).is_empty());
        // none listed any more
        h.own_swept(None, T0 + 3 * AFTER);
        let due = h.due(T0 + 3 * AFTER);
        assert_eq!(kinds(&due), vec![(Check::OwnListed, Kind::Recovered)]);
        assert_eq!(
            due[0].text(),
            "\u{2705} hik-f2b: no own address of hik-f2b is in the address-list any more \
             (after 30 min)"
        );
        // a short one says nothing
        h.own_swept(Some(stuck), T0 + 4 * AFTER);
        h.own_swept(None, T0 + 4 * AFTER + 60);
        assert!(h.due(T0 + 6 * AFTER).is_empty());
    }

    #[test]
    fn the_safe_list_rule_opens_and_ends_its_own_problem() {
        let mut h = health();
        let missing = "no rule in /ip/firewall/raw has src-address-list=cctv_safe: add one with \
                       action=accept above the drop rule for cctv_ban, in the same table";
        h.safe_rule_checked(&Err(missing.to_string()), T0);
        // a firewall check that passes says nothing about it
        h.firewall_checked(&Ok(String::new()), T0);
        let due = h.due(T0 + AFTER);
        assert_eq!(kinds(&due), vec![(Check::SafeRule, Kind::Alert)]);
        assert_eq!(
            due[0].text(),
            format!(
                "\u{26a0}\u{fe0f} hik-f2b: the safe list does not keep the own address from \
                 being blocked for 10 min: {}",
                missing
            )
        );
        h.safe_rule_checked(&Ok("found".to_string()), T0 + 2 * AFTER);
        let due = h.due(T0 + 2 * AFTER);
        assert_eq!(kinds(&due), vec![(Check::SafeRule, Kind::Recovered)]);
        assert_eq!(
            due[0].text(),
            "\u{2705} hik-f2b: the safe list keeps the own address from being blocked again \
             (after 20 min)"
        );
    }

    #[test]
    fn a_refused_safe_list_write_is_ended_only_by_a_write() {
        let mut h = health();
        let refused = SafeWrite::Refused {
            ip: Ipv4Addr::new(192, 0, 2, 200),
            list: "cctv_safe",
            error: "refused: HTTP 400",
        };
        h.safe_written(refused, T0);
        // a firewall check, a ban, a poll: none of these end it
        h.firewall_checked(&Ok(String::new()), T0 + 60);
        h.ban_tried(BanAttempt::Accepted, T0 + 60);
        h.bans_ended(BansEnded::Complete, 0, T0 + 60);
        h.poll_ended(T0 + 60);
        let due = h.due(T0 + AFTER);
        assert_eq!(kinds(&due), vec![(Check::SafeRefused, Kind::Alert)]);
        assert_eq!(
            due[0].text(),
            "\u{26a0}\u{fe0f} hik-f2b: the firewall refuses to write the own address to the safe \
             list for 10 min: 192.0.2.200 cannot be written to cctv_safe: refused: HTTP 400"
        );
        h.safe_written(SafeWrite::Written, T0 + 2 * AFTER);
        let due = h.due(T0 + 2 * AFTER);
        assert_eq!(kinds(&due), vec![(Check::SafeRefused, Kind::Recovered)]);
        assert_eq!(
            due[0].text(),
            "\u{2705} hik-f2b: the firewall writes the own address to the safe list again \
             (after 20 min)"
        );
        // a write says nothing about the firewall
        h.firewall_checked(
            &Err(HealthError::Unusable("timeout".into())),
            T0 + 3 * AFTER,
        );
        h.safe_written(SafeWrite::Written, T0 + 3 * AFTER);
        assert_eq!(
            kinds(&h.due(T0 + 4 * AFTER)),
            vec![(Check::Firewall, Kind::Alert)]
        );
    }

    #[test]
    fn recoveries_come_in_the_order_reported() {
        let mut h = health();
        h.nvr_polled("nvr1", NvrRead::Failed("x"), T0);
        h.firewall_checked(&Err(HealthError::NotEnforced("x".into())), T0);
        // a bypass passes the firewall check: reported before it fails
        bypass(&mut h, None, T0);
        h.ban_tried(BanAttempt::Unreachable("x"), T0);
        h.bans_ended(BansEnded::RateLimited, 1, T0);
        h.poll_ended(T0);
        assert_eq!(h.due(T0 + AFTER).len(), 5);
        let now = T0 + 2 * AFTER;
        h.nvr_polled("nvr1", NvrRead::Read, now);
        h.ban_tried(BanAttempt::Accepted, now);
        h.bans_ended(BansEnded::Complete, 0, now);
        h.poll_ended(now);
        h.firewall_checked(&Ok(String::new()), now);
        assert_eq!(
            kinds(&h.due(now)),
            vec![
                (nvr("nvr1"), Kind::Recovered),
                (Check::Firewall, Kind::Recovered),
                (Check::RateLimit, Kind::Recovered),
                (Check::Bypassed, Kind::Recovered),
                (Check::Rule, Kind::Recovered),
            ]
        );
    }

    /// A firewall check round is told in the order the round ran: the
    /// write of the safe list, the check, the safe list's rule, the own
    /// addresses. What a round did not get to leaves its problem as it is.
    #[test]
    fn a_round_is_told_in_the_order_it_ran() {
        let ip = Ipv4Addr::new(192, 0, 2, 200);
        let mut h = health();
        h.round_ended(
            &Ended {
                answered: true,
                safe: Some(SafeWritten::Refused {
                    ip,
                    list: "cctv_safe".to_string(),
                    error: "refused: x".to_string(),
                }),
                firewall: Err(HealthError::NotEnforced("no rule".to_string())),
                safe_rule: Some(Err("no accept rule".to_string())),
                own: Some(OwnSwept::Stuck {
                    ip,
                    list: "MikroTik address-list cctv_ban".to_string(),
                    error: "refused: y".to_string(),
                }),
                notifications: vec![],
            },
            T0,
        );
        assert_eq!(h.due(T0 + AFTER).len(), 4);
        // a round that got no further than the check
        let checked_only = Ended {
            answered: true,
            safe: None,
            firewall: Ok(String::new()),
            safe_rule: None,
            own: None,
            notifications: vec![],
        };
        h.round_ended(&checked_only, T0 + AFTER);
        assert_eq!(
            kinds(&h.due(T0 + AFTER)),
            vec![(Check::Rule, Kind::Recovered)]
        );
        assert_eq!(
            h.alerted(),
            vec!["own-address-listed", "safe-list-rule", "safe-list-refused"]
        );
        h.round_ended(
            &Ended {
                safe: Some(SafeWritten::Written),
                safe_rule: Some(Ok(String::new())),
                own: Some(OwnSwept::Clean),
                ..checked_only
            },
            T0 + 2 * AFTER,
        );
        assert_eq!(
            kinds(&h.due(T0 + 2 * AFTER)),
            vec![
                (Check::SafeRefused, Kind::Recovered),
                (Check::SafeRule, Kind::Recovered),
                (Check::OwnListed, Kind::Recovered),
            ]
        );
        assert_eq!(h.next_check, T0 + 2 * AFTER + HEALTH_CHECK_INTERVAL);
    }
}
