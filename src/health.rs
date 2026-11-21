//! Health alerts: when to tell someone that hik-f2b is not protecting
//! anything right now.
//!
//! The engine reports what it observes (`fail` / `pass`); this module only
//! decides when that is news. It does no I/O and takes the host time as an
//! argument, like `Engine::cycle_at`, so the policy can be tested on its own:
//!
//! - a problem is alerted once it has lasted `alert_after`, not before;
//! - while it persists, a reminder at most every `REMIND_EVERY`;
//! - one "recovered" notice when an alerted problem goes away; a problem
//!   that clears before it was alerted produces nothing;
//! - a problem that can no longer be observed is withdrawn: one "unknown"
//!   notice if it was alerted, nothing otherwise, and no more reminders.
//!
//! State is kept in memory only.

use crate::util;
use std::collections::BTreeMap;

/// How often an alerted problem that persists is reported again.
pub const REMIND_EVERY: u64 = 86400;
/// Longest reason kept for a notice.
const MAX_REASON: usize = 150;
/// Said when every refused ban has expired or been dropped while the
/// problem was alerted: nothing is left to show whether it is over.
const BAN_REFUSED_UNKNOWN: &str = "no refused ban is waiting any more; whether the firewall \
                                   accepts bans is not known until the next ban";

/// What is being watched. Each value is one problem with a stable key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Check {
    /// The NVR of that name cannot be read: unreachable, or our login is
    /// rejected.
    Nvr(String),
    /// The firewall cannot be reached, refuses our login or answers with an
    /// error.
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
    /// `alert_after` (see `Engine::bypass_over`).
    Bypassed,
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
        }
    }

    /// What is said when an alerted problem can no longer be observed.
    fn unknown(&self) -> String {
        match self {
            Check::BanRefused => BAN_REFUSED_UNKNOWN.to_string(),
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
/// wherever it stands: after a space, in brackets or quotes, after `=`. The
/// rest is printable ASCII and short. An address with a port outside a URL
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
    util::sanitize(&out, MAX_REASON)
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
        assert_eq!(clean_reason("a\nb\u{442}"), "a?b?");
        assert_eq!(clean_reason(&"x".repeat(500)).len(), MAX_REASON);
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
}
