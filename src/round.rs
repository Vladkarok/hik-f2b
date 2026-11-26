//! The firewall check round: a firewall check, and, when the router
//! answered it, the write of the safe list and the look-up of the own
//! addresses in the address-list. It runs at the start of the service and
//! then whenever health says a firewall check is due (`Health::check_due`).
//!
//! The round asks the firewall itself (`Firewall`, `action.rs`) and writes
//! its log lines itself. It keeps what it has to remember from one round to
//! the next: the own addresses it has kept in the safe list, and the own
//! addresses it has reported as listed. It gives the engine one `Ended`,
//! which the engine passes on to health (`Health::round_ended`) and, for
//! the notifications, to the outbox. It needs no clock: the time is only
//! for health.
//!
//! The rules:
//!
//! - a router that cannot be used (`HealthError::Unusable`) is asked
//!   nothing more; one without a drop rule (`HealthError::NotEnforced`) has
//!   answered, so the write of the safe list and the look-up still run;
//! - with a safe list, each own address toward the router is kept in it
//!   for `SAFE_TIMEOUT` (ADR 0006); an address that is no longer an own
//!   address is left to expire, and that is said once;
//! - a write that finds the router unusable makes the check a failed one
//!   and ends the writes; the look-up of the own addresses still runs;
//! - a refused write goes on with the next address and is the health
//!   problem `safe-list-refused`;
//! - each own address found in the address-list is removed: the only ban
//!   hik-f2b removes (ADR 0005). One that stays listed (a dry run, or a
//!   removal that failed) is reported once while it stays listed;
//! - a look-up that fails leaves the problem `own-address-listed` as it is;
//! - a dry run says what it would write or remove, and writes nothing;
//! - the stop flag is looked at before each request after the check.

use crate::action::{BanError, Firewall, HealthError, Kept, Removal};
use crate::health::{self, HEALTH_CHECK_INTERVAL};
use crate::util;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};

/// The timeout of the own address's entry in the safe list: six firewall
/// checks. It is renewed at every check the router answers, so it outlives
/// five checks in a row that fail (a router that restarts, a network that
/// is down for 25 minutes), and an address that is no longer the host's
/// stays safe for at most half an hour.
pub const SAFE_TIMEOUT: u64 = 6 * HEALTH_CHECK_INTERVAL;

/// Which firewall check this is. They differ only in their log lines: the
/// one at the start is written at INFO and ERROR, the periodic one at
/// DEBUG and WARNING.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum When {
    /// The check at the start of the service.
    Start,
    /// A periodic check.
    Periodic,
}

/// How the write of the safe list ended, when health is to hear of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SafeWritten {
    /// Every own address toward the router is in the safe list.
    Written,
    /// The firewall refused to write this one (the last one refused).
    Refused {
        ip: Ipv4Addr,
        /// The safe list's name.
        list: String,
        error: String,
    },
}

/// How the look-up of the own addresses ended, when every one was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnSwept {
    /// Every own address listed was removed, or none was listed.
    Clean,
    /// This one is still listed after its removal failed (the last one).
    Stuck {
        ip: Ipv4Addr,
        /// The address-list, as the firewall describes it.
        list: String,
        error: String,
    },
}

/// What a round came to, for health and the outbox.
#[derive(Clone, Debug, PartialEq)]
pub struct Ended {
    /// Whether the router answered the check (also when no rule blocks the
    /// address-list), so that more can be asked of it without waiting for a
    /// second timeout.
    pub answered: bool,
    /// The write of the safe list, if it ran to its end: not without a safe
    /// list or own address toward the router, not in a dry run, not when
    /// the router turned out unusable or the service is stopping.
    pub safe: Option<SafeWritten>,
    /// The firewall check: what it found, or why the firewall cannot be
    /// relied on. A write of the safe list that finds the router unusable
    /// makes it `HealthError::Unusable`.
    pub firewall: Result<String, HealthError>,
    /// The check of the safe list's rule, if it was made.
    pub safe_rule: Option<Result<String, String>>,
    /// The look-up of the own addresses, if every one was asked.
    pub own: Option<OwnSwept>,
    /// The notifications to queue, in this order.
    pub notifications: Vec<String>,
}

/// What the round remembers from one firewall check to the next.
#[derive(Debug, Default)]
pub struct Round {
    /// Own addresses found in the address-list and reported, that are not
    /// removed (a dry run, or a removal that failed): reported once while
    /// they stay listed.
    own_reported: BTreeSet<Ipv4Addr>,
    /// The own addresses toward the router that have been kept in the safe
    /// list (or, in a dry run, said to be kept).
    safe_kept: BTreeSet<Ipv4Addr>,
}

impl Round {
    pub fn new() -> Round {
        Round::default()
    }

    /// One round on `fw`: the check, and, when the router answered it and
    /// `stop` is not set, the write of the safe list for `toward_router`
    /// (`OwnAddresses::toward_router`) and the look-up of `to_ask`
    /// (`OwnAddresses::to_ask`) in the address-list. With `dry_run`
    /// nothing is written or removed.
    pub fn run(
        &mut self,
        fw: &dyn Firewall,
        when: When,
        toward_router: &[Ipv4Addr],
        to_ask: &[Ipv4Addr],
        dry_run: bool,
        stop: &AtomicBool,
    ) -> Ended {
        let stopping = || stop.load(Ordering::Relaxed);
        let (firewall, safe_rule) = match fw.check() {
            Ok(checked) => (Ok(checked.found), checked.safe_rule),
            Err(e) => (Err(e), None),
        };
        let answered = match &firewall {
            Ok(found) => {
                log_ok(when, found, &safe_rule);
                true
            }
            Err(e) => {
                log_failed(when, e);
                matches!(e, HealthError::NotEnforced(_))
            }
        };
        let mut ended = Ended {
            answered,
            safe: None,
            firewall,
            safe_rule,
            own: None,
            notifications: Vec::new(),
        };
        if answered && !stopping() {
            match self.keep_safe(fw, toward_router, dry_run, stop) {
                Ok(safe) => ended.safe = safe,
                // The firewall problem stays open rather than passing at
                // the check and failing at the write a moment later.
                Err(e) => ended.firewall = Err(HealthError::Unusable(e)),
            }
        }
        if answered && !stopping() {
            ended.own = self.sweep_own(fw, to_ask, dry_run, stop, &mut ended.notifications);
        }
        ended
    }

    /// With a safe list, keeps each own address of `addresses` in it for
    /// `SAFE_TIMEOUT`: a look-up and a renewal or an add per address. An
    /// address kept before that is not in `addresses` any more is left to
    /// expire. Without a safe list nothing is done and nothing is sent. A
    /// dry run sends nothing and says once per address what it would do.
    /// `Ok` carries what health is to hear, if anything; `Err` the error of
    /// a router that cannot be used, which ends the writes.
    fn keep_safe(
        &mut self,
        fw: &dyn Firewall,
        addresses: &[Ipv4Addr],
        dry_run: bool,
        stop: &AtomicBool,
    ) -> Result<Option<SafeWritten>, String> {
        let Some(list) = fw.safe_list() else {
            return Ok(None);
        };
        let timeout = util::fmt_timeout(SAFE_TIMEOUT);
        for ip in self.safe_kept.iter().filter(|ip| !addresses.contains(ip)) {
            crate::info!(
                "{} is no longer the own address toward the router: its entry in the safe list \
                 {} is left to expire",
                ip,
                list
            );
        }
        self.safe_kept.retain(|ip| addresses.contains(ip));
        if addresses.is_empty() {
            // Nothing to write: the router is on this host, or the address
            // toward it was never found (the look-up says why).
            return Ok(None);
        }
        if dry_run {
            for ip in addresses {
                if self.safe_kept.insert(*ip) {
                    crate::info!(
                        "DRY RUN: would keep {} in the safe list {} for {}, renewed at every \
                         firewall check",
                        ip,
                        list,
                        timeout
                    );
                }
            }
            return Ok(None);
        }
        let mut refused: Option<(Ipv4Addr, String)> = None;
        for &ip in addresses {
            if stop.load(Ordering::Relaxed) {
                return Ok(None);
            }
            match fw.keep_safe(ip, SAFE_TIMEOUT) {
                Ok(kept) => {
                    match kept {
                        Kept::Added => {
                            crate::info!("{} added to the safe list {} for {}", ip, list, timeout)
                        }
                        Kept::Renewed => {
                            crate::debug!(
                                "{} renewed in the safe list {} for {}",
                                ip,
                                list,
                                timeout
                            )
                        }
                        Kept::Left => crate::debug!(
                            "{} is in the safe list {} without a timeout (added by hand): the \
                             entry is left as it is",
                            ip,
                            list
                        ),
                    }
                    self.safe_kept.insert(ip);
                }
                Err(e) => {
                    let error = e.to_string();
                    crate::error!(
                        "cannot write own address {} to the safe list {}, will retry at the next \
                         firewall check: {}",
                        ip,
                        list,
                        error
                    );
                    if !matches!(e, BanError::Refused(_)) {
                        return Err(error);
                    }
                    refused = Some((ip, error));
                }
            }
        }
        Ok(Some(match refused {
            None => SafeWritten::Written,
            Some((ip, error)) => SafeWritten::Refused { ip, list, error },
        }))
    }

    /// Asks the firewall whether an own address of `addresses` is in the
    /// address-list, one request per address, and removes each one found.
    /// Each removal is a WARNING and a notification at once. In a dry run
    /// it is reported (once while it stays listed) and not removed. A
    /// removal that fails is an ERROR, a notification once while the
    /// address stays listed and, for health, `OwnSwept::Stuck`. A look-up
    /// that fails, or a stop, ends the round with `None`: not every own
    /// address was asked.
    fn sweep_own(
        &mut self,
        fw: &dyn Firewall,
        addresses: &[Ipv4Addr],
        dry_run: bool,
        stop: &AtomicBool,
        notifications: &mut Vec<String>,
    ) -> Option<OwnSwept> {
        self.own_reported.retain(|ip| addresses.contains(ip));
        let list = fw.describe();
        let mut stuck: Option<(Ipv4Addr, String)> = None;
        for &ip in addresses {
            if stop.load(Ordering::Relaxed) {
                return None;
            }
            let removal = if dry_run {
                match fw.own_listed(ip) {
                    Ok(true) => {
                        self.listed_in_dry_run(ip, &list, notifications);
                        continue;
                    }
                    Ok(false) => Removal::NotListed,
                    Err(e) => Removal::LookUpFailed(e),
                }
            } else {
                fw.remove_own(ip)
            };
            match removal {
                Removal::LookUpFailed(e) => {
                    crate::warn!(
                        "cannot ask {} whether own address {} is listed: {}",
                        list,
                        ip,
                        e
                    );
                    return None;
                }
                Removal::NotListed => {
                    self.own_reported.remove(&ip);
                }
                Removal::Removed => {
                    self.own_reported.remove(&ip);
                    crate::warn!(
                        "{} is an own address of hik-f2b and was in {}: the entry is removed",
                        ip,
                        list
                    );
                    notifications.push(format!(
                        "\u{26a0}\u{fe0f} hik-f2b: {} is an own address of hik-f2b and was in {}; \
                         the entry is removed. hik-f2b never bans its own addresses: it was added \
                         by hand, by another tool or by an earlier version.",
                        ip, list
                    ));
                }
                Removal::Failed(e) => {
                    let error = e.to_string();
                    crate::error!(
                        "cannot remove own address {} from {}, will retry at the next firewall \
                         check: {}",
                        ip,
                        list,
                        error
                    );
                    if self.own_reported.insert(ip) {
                        notifications.push(format!(
                            "\u{26a0}\u{fe0f} hik-f2b: {} is an own address of hik-f2b and is in \
                             {}, and cannot be removed: {}. Remove it by hand.",
                            ip,
                            list,
                            health::clean_reason(&error)
                        ));
                    }
                    stuck = Some((ip, error));
                }
            }
        }
        Some(match stuck {
            None => OwnSwept::Clean,
            Some((ip, error)) => OwnSwept::Stuck { ip, list, error },
        })
    }

    /// A dry run found own address `ip` in `list`: it is not removed, and
    /// is reported once while it stays listed.
    fn listed_in_dry_run(&mut self, ip: Ipv4Addr, list: &str, notifications: &mut Vec<String>) {
        if self.own_reported.insert(ip) {
            crate::warn!(
                "DRY RUN: {} is an own address of hik-f2b and is in {}: it would be removed",
                ip,
                list
            );
            notifications.push(format!(
                "\u{26a0}\u{fe0f} hik-f2b: {} is an own address of hik-f2b and is in {}. \
                 Dry run: it is not removed; remove it by hand.",
                ip, list
            ));
        }
    }
}

/// The log lines of a check the router answered with a drop rule.
fn log_ok(when: When, found: &str, safe_rule: &Option<Result<String, String>>) {
    match when {
        When::Start => {
            crate::info!("firewall check ok: {}", found);
            match safe_rule {
                Some(Ok(found)) => crate::info!("safe list check ok: {}", found),
                Some(Err(e)) => crate::error!("safe list check failed: {}", e),
                None => {}
            }
        }
        When::Periodic => {
            crate::debug!("firewall check ok: {}", found);
            match safe_rule {
                Some(Ok(found)) => crate::debug!("safe list check ok: {}", found),
                Some(Err(e)) => crate::warn!("safe list check failed: {}", e),
                None => {}
            }
        }
    }
}

/// The log line of a failed check.
fn log_failed(when: When, e: &HealthError) {
    match when {
        When::Start => crate::error!(
            "firewall check failed: {} (bans will keep being retried)",
            e
        ),
        When::Periodic => crate::warn!("firewall check failed: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{BanTime, Checked, SafeEntry};
    use crate::util::{self, capture_log, captured_log};
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    const A: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    const B: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 11);
    const LIST: &str = "test address-list cctv_ban";
    const SAFE: &str = "cctv_safe";

    /// An in-memory `Firewall`: the answers are set by the test, and every
    /// request the round makes is recorded. After `stop_after` requests it
    /// sets `stop`, as a signal would.
    struct Fake {
        check: Result<Checked, HealthError>,
        safe: Option<String>,
        kept: BTreeMap<Ipv4Addr, Result<Kept, BanError>>,
        listed: BTreeMap<Ipv4Addr, Result<bool, BanError>>,
        removal: BTreeMap<Ipv4Addr, Removal>,
        calls: RefCell<Vec<String>>,
        stop_after: Option<usize>,
        stop: AtomicBool,
    }

    impl Fake {
        fn new() -> Fake {
            Fake {
                check: Ok(Checked {
                    found: "1 rule".to_string(),
                    safe_rule: None,
                }),
                safe: Some(SAFE.to_string()),
                kept: BTreeMap::new(),
                listed: BTreeMap::new(),
                removal: BTreeMap::new(),
                calls: RefCell::new(Vec::new()),
                stop_after: None,
                stop: AtomicBool::new(false),
            }
        }

        fn call(&self, what: String) {
            let mut calls = self.calls.borrow_mut();
            calls.push(what);
            if self.stop_after == Some(calls.len()) {
                self.stop.store(true, Ordering::Relaxed);
            }
        }

        /// The requests made since the last call.
        fn calls(&self) -> Vec<String> {
            std::mem::take(&mut *self.calls.borrow_mut())
        }
    }

    impl Firewall for Fake {
        fn ban(&self, _: Ipv4Addr, _: BanTime, _: &str) -> Result<bool, BanError> {
            unreachable!("the round bans nothing")
        }
        fn check(&self) -> Result<Checked, HealthError> {
            self.call("check".to_string());
            self.check.clone()
        }
        fn safe_list(&self) -> Option<String> {
            self.safe.clone()
        }
        fn safe_entry(&self, _: Ipv4Addr) -> Result<Option<SafeEntry>, BanError> {
            unreachable!("only --check asks for the entry")
        }
        fn keep_safe(&self, ip: Ipv4Addr, timeout: u64) -> Result<Kept, BanError> {
            assert_eq!(timeout, SAFE_TIMEOUT);
            self.call(format!("keep_safe {}", ip));
            self.kept.get(&ip).cloned().unwrap_or(Ok(Kept::Renewed))
        }
        fn own_listed(&self, ip: Ipv4Addr) -> Result<bool, BanError> {
            self.call(format!("own_listed {}", ip));
            self.listed.get(&ip).cloned().unwrap_or(Ok(false))
        }
        fn remove_own(&self, ip: Ipv4Addr) -> Removal {
            self.call(format!("remove_own {}", ip));
            self.removal.get(&ip).cloned().unwrap_or(Removal::NotListed)
        }
        fn count(&self) -> Result<usize, String> {
            unreachable!("the round counts nothing")
        }
        fn describe(&self) -> String {
            LIST.to_string()
        }
    }

    /// One round on `fw`, with `own` as the own addresses both toward the
    /// router and to ask, as most tests need.
    fn run(round: &mut Round, fw: &Fake, when: When, own: &[Ipv4Addr], dry_run: bool) -> Ended {
        round.run(fw, when, own, own, dry_run, &fw.stop)
    }

    /// From now on, keep this thread's log lines. The DEBUG lines are
    /// checked too; the tests of the outbox and the log reader turn them on
    /// as well, and no test needs them off.
    fn capture() {
        util::set_verbose(true);
        capture_log();
    }

    /// The log lines since the last call, without the line of a periodic
    /// check that found the drop rule, which every round here starts with
    /// (the lines of the check have a test of their own).
    fn logged() -> Vec<String> {
        captured_log()
            .into_iter()
            .filter(|line| line != "DEBUG firewall check ok: 1 rule")
            .collect()
    }

    fn ok(found: &str) -> Result<String, HealthError> {
        Ok(found.to_string())
    }

    fn refused(error: &str) -> Removal {
        Removal::Failed(BanError::Refused(error.to_string()))
    }

    #[test]
    fn a_router_that_cannot_be_used_is_asked_nothing_more() {
        capture();
        let mut fw = Fake::new();
        fw.check = Err(HealthError::Unusable("timed out".to_string()));
        let ended = run(&mut Round::new(), &fw, When::Start, &[A], false);
        assert_eq!(fw.calls(), ["check"]);
        assert_eq!(
            ended,
            Ended {
                answered: false,
                safe: None,
                firewall: Err(HealthError::Unusable("timed out".to_string())),
                safe_rule: None,
                own: None,
                notifications: vec![],
            }
        );
        assert_eq!(
            logged(),
            ["ERROR firewall check failed: timed out (bans will keep being retried)"]
        );
        let again = run(&mut Round::new(), &fw, When::Periodic, &[A], false);
        assert_eq!(fw.calls(), ["check"]);
        assert_eq!(again, ended);
        assert_eq!(logged(), ["WARNING firewall check failed: timed out"]);
    }

    #[test]
    fn a_router_without_a_drop_rule_has_answered() {
        capture();
        let mut fw = Fake::new();
        fw.check = Err(HealthError::NotEnforced("no rule".to_string()));
        let ended = run(&mut Round::new(), &fw, When::Periodic, &[A], false);
        assert_eq!(
            fw.calls(),
            ["check", "keep_safe 192.0.2.10", "remove_own 192.0.2.10"]
        );
        assert!(ended.answered);
        assert_eq!(
            ended.firewall,
            Err(HealthError::NotEnforced("no rule".to_string()))
        );
        assert_eq!(ended.safe, Some(SafeWritten::Written));
        assert_eq!(ended.own, Some(OwnSwept::Clean));
        assert_eq!(
            logged(),
            [
                "WARNING firewall check failed: no rule",
                "DEBUG 192.0.2.10 renewed in the safe list cctv_safe for 00:30:00"
            ]
        );
    }

    #[test]
    fn the_start_and_the_periodic_check_differ_only_in_their_log_lines() {
        capture();
        let mut fw = Fake::new();
        // the check of the safe list's rule, the lines at the start, the
        // lines of a periodic check
        type Case = (
            Option<Result<String, String>>,
            Vec<&'static str>,
            Vec<&'static str>,
        );
        let cases: [Case; 3] = [
            (
                None,
                vec!["INFO firewall check ok: 1 rule"],
                vec!["DEBUG firewall check ok: 1 rule"],
            ),
            (
                Some(Ok("1 accept rule".to_string())),
                vec![
                    "INFO firewall check ok: 1 rule",
                    "INFO safe list check ok: 1 accept rule",
                ],
                vec![
                    "DEBUG firewall check ok: 1 rule",
                    "DEBUG safe list check ok: 1 accept rule",
                ],
            ),
            (
                Some(Err("no accept rule".to_string())),
                vec![
                    "INFO firewall check ok: 1 rule",
                    "ERROR safe list check failed: no accept rule",
                ],
                vec![
                    "DEBUG firewall check ok: 1 rule",
                    "WARNING safe list check failed: no accept rule",
                ],
            ),
        ];
        for (safe_rule, start, periodic) in cases {
            fw.check = Ok(Checked {
                found: "1 rule".to_string(),
                safe_rule: safe_rule.clone(),
            });
            // no own address: only the lines of the check
            let at_start = run(&mut Round::new(), &fw, When::Start, &[], false);
            assert_eq!(captured_log(), start);
            let calls = fw.calls();
            let later = run(&mut Round::new(), &fw, When::Periodic, &[], false);
            assert_eq!(captured_log(), periodic);
            assert_eq!(fw.calls(), calls);
            assert_eq!(later, at_start);
            assert_eq!(at_start.firewall, ok("1 rule"));
            assert_eq!(at_start.safe_rule, safe_rule);
        }
    }

    #[test]
    fn each_own_address_toward_the_router_is_kept_in_the_safe_list() {
        capture();
        let mut fw = Fake::new();
        let c = Ipv4Addr::new(192, 0, 2, 12);
        fw.kept.insert(A, Ok(Kept::Added));
        fw.kept.insert(B, Ok(Kept::Renewed));
        fw.kept.insert(c, Ok(Kept::Left));
        let ended = Round::new().run(&fw, When::Periodic, &[A, B, c], &[], false, &fw.stop);
        assert_eq!(
            fw.calls(),
            [
                "check",
                "keep_safe 192.0.2.10",
                "keep_safe 192.0.2.11",
                "keep_safe 192.0.2.12"
            ]
        );
        assert_eq!(ended.safe, Some(SafeWritten::Written));
        assert_eq!(ended.firewall, ok("1 rule"));
        assert_eq!(
            logged(),
            [
                "INFO 192.0.2.10 added to the safe list cctv_safe for 00:30:00",
                "DEBUG 192.0.2.11 renewed in the safe list cctv_safe for 00:30:00",
                "DEBUG 192.0.2.12 is in the safe list cctv_safe without a timeout (added by \
                 hand): the entry is left as it is"
            ]
        );
    }

    #[test]
    fn without_a_safe_list_or_an_address_toward_the_router_nothing_is_written() {
        let mut fw = Fake::new();
        let ended = Round::new().run(&fw, When::Periodic, &[], &[A], false, &fw.stop);
        assert_eq!(fw.calls(), ["check", "remove_own 192.0.2.10"]);
        assert_eq!(ended.safe, None);
        fw.safe = None;
        let ended = Round::new().run(&fw, When::Periodic, &[A], &[A], false, &fw.stop);
        assert_eq!(fw.calls(), ["check", "remove_own 192.0.2.10"]);
        assert_eq!(ended.safe, None);
    }

    #[test]
    fn an_address_that_is_no_longer_own_is_left_to_expire_and_said_once() {
        capture();
        let fw = Fake::new();
        let mut round = Round::new();
        run(&mut round, &fw, When::Periodic, &[A, B], false);
        fw.calls();
        logged();
        let ended = run(&mut round, &fw, When::Periodic, &[A], false);
        assert_eq!(
            fw.calls(),
            ["check", "keep_safe 192.0.2.10", "remove_own 192.0.2.10"]
        );
        assert_eq!(ended.safe, Some(SafeWritten::Written));
        let renewed = "DEBUG 192.0.2.10 renewed in the safe list cctv_safe for 00:30:00";
        assert_eq!(
            logged(),
            [
                "INFO 192.0.2.11 is no longer the own address toward the router: its entry in \
                 the safe list cctv_safe is left to expire",
                renewed
            ]
        );
        run(&mut round, &fw, When::Periodic, &[A], false);
        assert_eq!(logged(), [renewed]);
        // also when no address toward the router is known any more
        run(&mut round, &fw, When::Periodic, &[], false);
        assert_eq!(
            logged(),
            [
                "INFO 192.0.2.10 is no longer the own address toward the router: its entry in \
              the safe list cctv_safe is left to expire"
            ]
        );
        run(&mut round, &fw, When::Periodic, &[], false);
        assert_eq!(logged(), Vec::<String>::new());
    }

    #[test]
    fn a_write_that_finds_the_router_unusable_fails_the_check_and_ends_the_writes() {
        capture();
        let mut fw = Fake::new();
        fw.kept
            .insert(A, Err(BanError::Transport("timed out".to_string())));
        let ended = run(&mut Round::new(), &fw, When::Periodic, &[A, B], false);
        // no write for B; the look-up of the own addresses still runs
        assert_eq!(
            fw.calls(),
            [
                "check",
                "keep_safe 192.0.2.10",
                "remove_own 192.0.2.10",
                "remove_own 192.0.2.11"
            ]
        );
        assert!(ended.answered);
        assert_eq!(
            ended.firewall,
            Err(HealthError::Unusable(
                "cannot reach the firewall: timed out".to_string()
            ))
        );
        assert_eq!(ended.safe, None);
        assert_eq!(ended.own, Some(OwnSwept::Clean));
        assert_eq!(
            logged(),
            [
                "ERROR cannot write own address 192.0.2.10 to the safe list cctv_safe, will \
              retry at the next firewall check: cannot reach the firewall: timed out"
            ]
        );
    }

    #[test]
    fn a_refused_write_goes_on_with_the_next_address() {
        capture();
        let mut fw = Fake::new();
        fw.kept.insert(A, Err(BanError::Refused("no".to_string())));
        fw.kept.insert(B, Ok(Kept::Added));
        let ended = Round::new().run(&fw, When::Periodic, &[A, B], &[], false, &fw.stop);
        assert_eq!(
            fw.calls(),
            ["check", "keep_safe 192.0.2.10", "keep_safe 192.0.2.11"]
        );
        assert_eq!(ended.firewall, ok("1 rule"));
        assert_eq!(
            ended.safe,
            Some(SafeWritten::Refused {
                ip: A,
                list: SAFE.to_string(),
                error: "refused: no".to_string(),
            })
        );
        assert_eq!(
            logged(),
            [
                "ERROR cannot write own address 192.0.2.10 to the safe list cctv_safe, will \
                 retry at the next firewall check: refused: no",
                "INFO 192.0.2.11 added to the safe list cctv_safe for 00:30:00"
            ]
        );
        // two refused: health hears of the last one
        fw.kept
            .insert(B, Err(BanError::Refused("no either".to_string())));
        let ended = Round::new().run(&fw, When::Periodic, &[A, B], &[], false, &fw.stop);
        assert_eq!(
            ended.safe,
            Some(SafeWritten::Refused {
                ip: B,
                list: SAFE.to_string(),
                error: "refused: no either".to_string(),
            })
        );
    }

    #[test]
    fn a_listed_own_address_is_removed_and_said_at_once() {
        capture();
        let mut fw = Fake::new();
        fw.safe = None;
        fw.removal.insert(A, Removal::Removed);
        let mut round = Round::new();
        let removed = "\u{26a0}\u{fe0f} hik-f2b: 192.0.2.10 is an own address of hik-f2b and was \
                       in test address-list cctv_ban; the entry is removed. hik-f2b never bans \
                       its own addresses: it was added by hand, by another tool or by an \
                       earlier version.";
        // each removal, every time
        for _ in 0..2 {
            let ended = run(&mut round, &fw, When::Periodic, &[A, B], false);
            assert_eq!(
                fw.calls(),
                ["check", "remove_own 192.0.2.10", "remove_own 192.0.2.11"]
            );
            assert_eq!(ended.own, Some(OwnSwept::Clean));
            assert_eq!(ended.notifications, [removed]);
            assert_eq!(
                logged(),
                [
                    "WARNING 192.0.2.10 is an own address of hik-f2b and was in test \
                  address-list cctv_ban: the entry is removed"
                ]
            );
        }
    }

    #[test]
    fn a_failed_removal_is_reported_once_while_the_address_stays_listed() {
        capture();
        let mut fw = Fake::new();
        fw.safe = None;
        let error = "HTTP 403 from https://192.0.2.1/rest";
        fw.removal.insert(A, refused(error));
        let stuck = Some(OwnSwept::Stuck {
            ip: A,
            list: LIST.to_string(),
            error: format!("refused: {}", error),
        });
        let line = "ERROR cannot remove own address 192.0.2.10 from test address-list cctv_ban, \
                    will retry at the next firewall check: refused: HTTP 403 from \
                    https://192.0.2.1/rest";
        // the URL is masked in the chat, as in a health alert
        let text = "\u{26a0}\u{fe0f} hik-f2b: 192.0.2.10 is an own address of hik-f2b and is in \
                    test address-list cctv_ban, and cannot be removed: refused: HTTP 403 from \
                    <url>. Remove it by hand.";
        let mut round = Round::new();
        let ended = run(&mut round, &fw, When::Periodic, &[A, B], false);
        // the next address is still asked
        assert_eq!(
            fw.calls(),
            ["check", "remove_own 192.0.2.10", "remove_own 192.0.2.11"]
        );
        assert_eq!(ended.own, stuck);
        assert_eq!(ended.notifications, [text]);
        assert_eq!(logged(), [line]);
        // still listed: logged and a health problem, not notified again
        let ended = run(&mut round, &fw, When::Periodic, &[A, B], false);
        assert_eq!(ended.own, stuck);
        assert!(ended.notifications.is_empty());
        assert_eq!(logged(), [line]);
        // gone, then listed again: notified again
        fw.removal.insert(A, Removal::NotListed);
        let ended = run(&mut round, &fw, When::Periodic, &[A, B], false);
        assert_eq!(ended.own, Some(OwnSwept::Clean));
        assert!(ended.notifications.is_empty());
        fw.removal.insert(A, refused(error));
        let ended = run(&mut round, &fw, When::Periodic, &[A, B], false);
        assert_eq!(ended.notifications, [text]);
        // an address that is no longer own is forgotten as well
        run(&mut round, &fw, When::Periodic, &[B], false);
        let ended = run(&mut round, &fw, When::Periodic, &[A, B], false);
        assert_eq!(ended.notifications, [text]);
    }

    #[test]
    fn a_failed_look_up_leaves_the_problem_as_it_is() {
        capture();
        let mut fw = Fake::new();
        fw.safe = None;
        fw.removal.insert(
            A,
            Removal::LookUpFailed(BanError::Login("HTTP 401".to_string())),
        );
        let ended = run(&mut Round::new(), &fw, When::Periodic, &[A, B], false);
        // not every own address was asked: health hears nothing of it
        assert_eq!(fw.calls(), ["check", "remove_own 192.0.2.10"]);
        assert_eq!(ended.own, None);
        assert_eq!(ended.firewall, ok("1 rule"));
        assert!(ended.notifications.is_empty());
        assert_eq!(
            logged(),
            [
                "WARNING cannot ask test address-list cctv_ban whether own address 192.0.2.10 is \
              listed: the firewall refuses our login: HTTP 401"
            ]
        );
        // in a dry run as well
        fw.listed
            .insert(A, Err(BanError::Login("HTTP 401".to_string())));
        let ended = run(&mut Round::new(), &fw, When::Periodic, &[A, B], true);
        assert_eq!(fw.calls(), ["check", "own_listed 192.0.2.10"]);
        assert_eq!(ended.own, None);
        assert_eq!(logged().len(), 1);
    }

    #[test]
    fn a_dry_run_says_what_it_would_do_and_writes_nothing() {
        capture();
        let mut fw = Fake::new();
        fw.listed.insert(A, Ok(true));
        let text = "\u{26a0}\u{fe0f} hik-f2b: 192.0.2.10 is an own address of hik-f2b and is in \
                    test address-list cctv_ban. Dry run: it is not removed; remove it by hand.";
        let mut round = Round::new();
        let ended = run(&mut round, &fw, When::Periodic, &[A, B], true);
        // only looks: no write to the safe list, no removal
        assert_eq!(
            fw.calls(),
            ["check", "own_listed 192.0.2.10", "own_listed 192.0.2.11"]
        );
        assert_eq!(ended.safe, None);
        assert_eq!(ended.own, Some(OwnSwept::Clean));
        assert_eq!(ended.notifications, [text]);
        assert_eq!(
            logged(),
            [
                "INFO DRY RUN: would keep 192.0.2.10 in the safe list cctv_safe for 00:30:00, \
                 renewed at every firewall check",
                "INFO DRY RUN: would keep 192.0.2.11 in the safe list cctv_safe for 00:30:00, \
                 renewed at every firewall check",
                "WARNING DRY RUN: 192.0.2.10 is an own address of hik-f2b and is in test \
                 address-list cctv_ban: it would be removed"
            ]
        );
        // said once
        let ended = run(&mut round, &fw, When::Periodic, &[A, B], true);
        assert_eq!(
            fw.calls(),
            ["check", "own_listed 192.0.2.10", "own_listed 192.0.2.11"]
        );
        assert!(ended.notifications.is_empty());
        assert_eq!(logged(), Vec::<String>::new());
        // no longer listed, then listed again: said again
        fw.listed.insert(A, Ok(false));
        run(&mut round, &fw, When::Periodic, &[A, B], true);
        fw.listed.insert(A, Ok(true));
        let ended = run(&mut round, &fw, When::Periodic, &[A, B], true);
        assert_eq!(ended.notifications, [text]);
        assert_eq!(logged().len(), 1);
    }

    #[test]
    fn the_stop_flag_is_looked_at_before_each_request() {
        // set during the check: nothing more is asked
        let mut fw = Fake::new();
        fw.stop_after = Some(1);
        let ended = run(&mut Round::new(), &fw, When::Start, &[A, B], false);
        assert_eq!(fw.calls(), ["check"]);
        assert!(ended.answered);
        assert_eq!((ended.safe, ended.own), (None, None));
        assert_eq!(ended.firewall, ok("1 rule"));
        // during the first write: the writes end, health hears of neither
        let mut fw = Fake::new();
        fw.stop_after = Some(2);
        let ended = run(&mut Round::new(), &fw, When::Periodic, &[A, B], false);
        assert_eq!(fw.calls(), ["check", "keep_safe 192.0.2.10"]);
        assert_eq!((ended.safe, ended.own), (None, None));
        // during the first look-up
        let mut fw = Fake::new();
        fw.safe = None;
        fw.stop_after = Some(2);
        let ended = run(&mut Round::new(), &fw, When::Periodic, &[A, B], false);
        assert_eq!(fw.calls(), ["check", "remove_own 192.0.2.10"]);
        assert_eq!(ended.own, None);
    }
}
