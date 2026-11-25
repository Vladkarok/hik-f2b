//! The host names of `ignoreip` and the addresses they resolve to, which
//! are never banned, like an address written in `ignoreip`.
//!
//! An administrator whose own address changes (a home connection) cannot
//! write it into `ignoreip`, but can write a name that follows it (a
//! dynamic DNS name). Each name is resolved at startup and then at most
//! every `names::RESOLVE_EVERY` of host time (`names::Names`), IPv4 only,
//! through the `own::Source` seam: the operating system's resolver in the
//! service, fixed answers in tests and the simulation.
//!
//! When a look-up fails, the addresses last found stay exempt; a name that
//! has never resolved exempts nothing. Both are logged once per stretch of
//! failures, a change of what a name resolves to is one INFO line, and an
//! address that a name no longer resolves to is not exempt any more.
//!
//! These addresses are a source of exemption only (ADR 0007): they are not
//! own addresses, so hik-f2b never removes a ban for them (ADR 0005) and
//! never writes them to the safe list (ADR 0006). The ban ledger is told
//! them with its rules and looks nothing up (`ledger::Rules`).

use crate::config::Config;
use crate::names::{Names, RESOLVE_EVERY};
use crate::own::Source;
use crate::util;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

/// Longest reason kept for a failed look-up.
const MAX_REASON: usize = 200;

/// `192.0.2.1 and 192.0.2.2`, or `none`.
fn list(addresses: &[Ipv4Addr]) -> String {
    if addresses.is_empty() {
        return "none".to_string();
    }
    addresses
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(" and ")
}

/// The host names of `ignoreip`, with what each last resolved to.
pub struct IgnoredNames {
    /// The names, in the order of the config.
    names: Vec<String>,
    source: Box<dyn Source>,
    lookups: Names,
    /// What each name last resolved to (empty if it never did).
    known: Vec<Vec<Ipv4Addr>>,
    /// Why the last look-up of each name failed (`None`: it worked).
    failures: Vec<Option<String>>,
    /// Every address a name resolves to, with the first name (in the order
    /// of the config) that resolves to it.
    addresses: BTreeMap<Ipv4Addr, String>,
}

impl IgnoredNames {
    /// The names of `cfg.ignore_names`, each looked up once through
    /// `source`. Nothing is logged (see `Engine::startup_names`).
    pub fn new(cfg: &Config, source: Box<dyn Source>) -> IgnoredNames {
        let n = cfg.ignore_names.len();
        let mut ignored = IgnoredNames {
            names: cfg.ignore_names.clone(),
            source,
            lookups: Names::new(),
            known: vec![Vec::new(); n],
            failures: vec![None; n],
            addresses: BTreeMap::new(),
        };
        ignored.look_up(None);
        ignored
    }

    /// Logs, at the start of the service, what each name resolves to and,
    /// for each that does not resolve, that it exempts nothing. Nothing
    /// without a name.
    pub fn log_start(&self) {
        if self.is_empty() {
            return;
        }
        crate::info!("ignoreip names, never banned: {}", self.describe());
        for (name, _, e) in self.each() {
            if let Some(e) = e {
                crate::warn!(
                    "ignoreip: {} does not resolve, so it exempts no address until it does; it \
                     is tried again every {} min: {}",
                    name,
                    RESOLVE_EVERY / 60,
                    e
                );
            }
        }
    }

    /// Whether `ignoreip` has no host name.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Looks every name up again at host time `now`, each only when its
    /// answer is `names::RESOLVE_EVERY` old. Logs a change of what a name
    /// resolves to (INFO), the first failed look-up of a stretch (WARNING)
    /// and the end of one without a change (INFO). A name that has never
    /// resolved failed at startup, and `log_start` said so: its stretch
    /// goes on until it resolves.
    pub fn refresh(&mut self, now: u64) {
        let known = self.known.clone();
        let failures = self.failures.clone();
        self.look_up(Some(now));
        for (i, name) in self.names.iter().enumerate() {
            let (was, now) = (&known[i], &self.known[i]);
            match (&failures[i], &self.failures[i]) {
                (None, Some(e)) => crate::warn!(
                    "ignoreip: the look-up of {} failed, the addresses it last resolved to stay \
                     exempt ({}): {}",
                    name,
                    list(now),
                    e
                ),
                _ if was != now => crate::info!(
                    "ignoreip: {} now resolves to {} (was {})",
                    name,
                    list(now),
                    list(was)
                ),
                (Some(_), None) => crate::info!(
                    "ignoreip: the look-up of {} works again, it still resolves to {}",
                    name,
                    list(now)
                ),
                _ => {}
            }
        }
    }

    /// One look-up of every name at host time `now` (`None` at startup).
    fn look_up(&mut self, now: Option<u64>) {
        let source = &mut self.source;
        for (i, name) in self.names.iter().enumerate() {
            // No connection goes to the name: the port is not used.
            let (known, error) = self
                .lookups
                .lookup(name, now, |host| source.resolve(host, 0));
            // An answer in another order is the same answer.
            let mut known = known;
            known.sort_unstable();
            known.dedup();
            self.known[i] = known;
            self.failures[i] = error.map(|e| util::printable(&e, MAX_REASON));
        }
        self.addresses = BTreeMap::new();
        for (name, known) in self.names.iter().zip(&self.known) {
            for ip in known {
                self.addresses.entry(*ip).or_insert_with(|| name.clone());
            }
        }
    }

    /// Every address a name resolves to, as last found, with the name (the
    /// first in the config, if several resolve to it). What the ledger is
    /// told.
    pub fn addresses(&self) -> &BTreeMap<Ipv4Addr, String> {
        &self.addresses
    }

    /// Each name, what it last resolved to and why its last look-up
    /// failed, if it did, in the order of the config.
    pub fn each(&self) -> impl Iterator<Item = (&str, &[Ipv4Addr], Option<&str>)> {
        self.names
            .iter()
            .zip(&self.known)
            .zip(&self.failures)
            .map(|((name, known), e)| (name.as_str(), known.as_slice(), e.as_deref()))
    }

    /// Why the last look-ups failed, by name (empty when all worked).
    pub fn failures(&self) -> Vec<String> {
        self.each()
            .filter_map(|(name, _, e)| e.map(|e| format!("{}: {}", name, e)))
            .collect()
    }

    /// What each name resolves to: `home.example.net 203.0.113.7,
    /// vpn.example.org 198.51.100.4 and 198.51.100.5`; a name that never
    /// resolved is `gone.example.net not resolved`.
    pub fn describe(&self) -> String {
        self.each()
            .map(|(name, known, _)| {
                if known.is_empty() {
                    format!("{} not resolved", name)
                } else {
                    format!("{} {}", name, list(known))
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::own::Fixed;
    use crate::util::{capture_log, captured_log};

    const T0: u64 = 1_768_000_000;
    const HOME: &str = "home.example.net";
    const VPN: &str = "vpn.example.org";

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    fn config(ignoreip: &str) -> Config {
        Config::parse(&format!(
            "[general]\nstate_file = /tmp/hik-f2b-ignored-test\nignoreip = {}\n\
             [nvr:nvr1]\nurl = http://192.0.2.10\nuser = f2b\npassword = x\n",
            ignoreip
        ))
        .unwrap()
    }

    fn addresses(ignored: &IgnoredNames) -> Vec<(String, String)> {
        ignored
            .addresses()
            .iter()
            .map(|(ip, name)| (ip.to_string(), name.clone()))
            .collect()
    }

    fn pair(ip: &str, name: &str) -> (String, String) {
        (ip.to_string(), name.to_string())
    }

    #[test]
    fn names_are_resolved_at_startup_without_a_log_line() {
        let fixed = Fixed::new(ip("192.0.2.200"));
        fixed.set_name(HOME, Ok(vec![ip("203.0.113.7")]));
        fixed.set_name(VPN, Ok(vec![ip("198.51.100.5"), ip("203.0.113.7")]));
        capture_log();
        let ignored = IgnoredNames::new(
            &config(&format!("192.168.0.0/16, {}, {}", HOME, VPN)),
            Box::new(fixed.clone()),
        );
        assert!(captured_log().is_empty());
        assert_eq!(fixed.resolved(), 2);
        assert!(!ignored.is_empty());
        // an address of two names is named after the first in the config
        assert_eq!(
            addresses(&ignored),
            [pair("198.51.100.5", VPN), pair("203.0.113.7", HOME)]
        );
        assert_eq!(
            ignored.describe(),
            "home.example.net 203.0.113.7, vpn.example.org 198.51.100.5 and 203.0.113.7"
        );
        assert!(ignored.failures().is_empty());
    }

    /// Without a name nothing is looked up.
    #[test]
    fn no_name_no_look_up() {
        let fixed = Fixed::new(ip("192.0.2.200"));
        let mut ignored = IgnoredNames::new(&config("203.0.113.7"), Box::new(fixed.clone()));
        capture_log();
        for poll in 0..20 {
            ignored.refresh(T0 + poll * RESOLVE_EVERY);
        }
        assert!(ignored.is_empty());
        assert!(ignored.addresses().is_empty());
        assert_eq!(fixed.resolved(), 0);
        assert!(captured_log().is_empty());
    }

    #[test]
    fn a_name_is_resolved_again_only_after_the_interval_and_a_change_is_one_line() {
        let fixed = Fixed::new(ip("192.0.2.200"));
        fixed.set_name(HOME, Ok(vec![ip("203.0.113.7")]));
        let mut ignored = IgnoredNames::new(&config(HOME), Box::new(fixed.clone()));
        capture_log();
        // the first poll gives the time of the look-up at startup
        ignored.refresh(T0);
        fixed.set_name(HOME, Ok(vec![ip("203.0.113.8")]));
        for poll in 1..10 {
            ignored.refresh(T0 + poll * 30);
        }
        ignored.refresh(T0 + RESOLVE_EVERY - 1);
        assert_eq!(fixed.resolved(), 1);
        assert_eq!(addresses(&ignored), [pair("203.0.113.7", HOME)]);
        assert!(captured_log().is_empty());
        ignored.refresh(T0 + RESOLVE_EVERY);
        assert_eq!(fixed.resolved(), 2);
        // the old address is no longer exempt
        assert_eq!(addresses(&ignored), [pair("203.0.113.8", HOME)]);
        assert_eq!(
            captured_log(),
            vec!["INFO ignoreip: home.example.net now resolves to 203.0.113.8 (was 203.0.113.7)"]
        );
        // the same answer again says nothing
        ignored.refresh(T0 + 2 * RESOLVE_EVERY);
        assert_eq!(fixed.resolved(), 3);
        assert!(captured_log().is_empty());
    }

    #[test]
    fn a_failed_look_up_keeps_the_last_answer_and_is_said_once() {
        let fixed = Fixed::new(ip("192.0.2.200"));
        fixed.set_name(HOME, Ok(vec![ip("203.0.113.7"), ip("203.0.113.9")]));
        let mut ignored = IgnoredNames::new(&config(HOME), Box::new(fixed.clone()));
        ignored.refresh(T0);
        capture_log();
        fixed.set_name(
            HOME,
            Err("cannot resolve home.example.net: timed out".into()),
        );
        ignored.refresh(T0 + RESOLVE_EVERY);
        assert_eq!(
            captured_log(),
            vec![
                "WARNING ignoreip: the look-up of home.example.net failed, the addresses it last \
                 resolved to stay exempt (203.0.113.7 and 203.0.113.9): cannot resolve \
                 home.example.net: timed out"
            ]
        );
        assert_eq!(
            addresses(&ignored),
            [pair("203.0.113.7", HOME), pair("203.0.113.9", HOME)]
        );
        assert_eq!(
            ignored.failures(),
            ["home.example.net: cannot resolve home.example.net: timed out"]
        );
        // the stretch goes on, with another reason too: nothing more
        ignored.refresh(T0 + 2 * RESOLVE_EVERY);
        fixed.set_name(HOME, Ok(vec![]));
        ignored.refresh(T0 + 3 * RESOLVE_EVERY);
        assert_eq!(
            ignored.failures(),
            ["home.example.net: home.example.net has no IPv4 address"]
        );
        assert!(captured_log().is_empty());
        assert_eq!(addresses(&ignored).len(), 2);
        // it works again, with the same answer
        fixed.set_name(HOME, Ok(vec![ip("203.0.113.9"), ip("203.0.113.7")]));
        ignored.refresh(T0 + 4 * RESOLVE_EVERY);
        assert_eq!(
            captured_log(),
            vec![
                "INFO ignoreip: the look-up of home.example.net works again, it still resolves \
                 to 203.0.113.7 and 203.0.113.9"
            ]
        );
        assert!(ignored.failures().is_empty());
        // a new stretch is said again; one that ends with another answer is
        // the line of the change
        fixed.set_name(HOME, Err("timed out".into()));
        ignored.refresh(T0 + 5 * RESOLVE_EVERY);
        fixed.set_name(HOME, Ok(vec![ip("203.0.113.8")]));
        ignored.refresh(T0 + 6 * RESOLVE_EVERY);
        assert_eq!(
            captured_log(),
            vec![
                "WARNING ignoreip: the look-up of home.example.net failed, the addresses it last \
                 resolved to stay exempt (203.0.113.7 and 203.0.113.9): timed out",
                "INFO ignoreip: home.example.net now resolves to 203.0.113.8 (was 203.0.113.7 \
                 and 203.0.113.9)",
            ]
        );
        assert_eq!(addresses(&ignored), [pair("203.0.113.8", HOME)]);
    }

    /// A name that has never resolved exempts nothing; the failure at the
    /// start is said by the start of the service, not again in each poll.
    #[test]
    fn a_name_never_resolved_exempts_nothing() {
        let fixed = Fixed::new(ip("192.0.2.200"));
        fixed.set_name(VPN, Ok(vec![ip("198.51.100.5")]));
        capture_log();
        let mut ignored = IgnoredNames::new(
            &config(&format!("{} {}", HOME, VPN)),
            Box::new(fixed.clone()),
        );
        assert_eq!(addresses(&ignored), [pair("198.51.100.5", VPN)]);
        assert_eq!(
            ignored.describe(),
            "home.example.net not resolved, vpn.example.org 198.51.100.5"
        );
        assert_eq!(
            ignored.failures(),
            ["home.example.net: cannot resolve home.example.net: no such name"]
        );
        for poll in 0..30 {
            ignored.refresh(T0 + poll * 30);
        }
        assert!(captured_log().is_empty());
        // at startup, and twice each in the polls (every `RESOLVE_EVERY`)
        assert_eq!(fixed.resolved(), 6);
        // it resolves at last: one line
        fixed.set_name(HOME, Ok(vec![ip("203.0.113.7")]));
        ignored.refresh(T0 + 3 * RESOLVE_EVERY);
        assert_eq!(
            captured_log(),
            vec!["INFO ignoreip: home.example.net now resolves to 203.0.113.7 (was none)"]
        );
        assert_eq!(
            addresses(&ignored),
            [pair("198.51.100.5", VPN), pair("203.0.113.7", HOME)]
        );
        // a name that resolved, then never again, after a start: the
        // stretch that begins in a poll is said once
        let fixed = Fixed::new(ip("192.0.2.200"));
        let mut ignored = IgnoredNames::new(&config(HOME), Box::new(fixed.clone()));
        ignored.refresh(T0);
        assert!(captured_log().is_empty());
        fixed.set_name(HOME, Ok(vec![ip("203.0.113.7")]));
        ignored.refresh(T0 + RESOLVE_EVERY);
        fixed.set_name(HOME, Err("no such name".into()));
        ignored.refresh(T0 + 2 * RESOLVE_EVERY);
        ignored.refresh(T0 + 3 * RESOLVE_EVERY);
        assert_eq!(
            captured_log(),
            vec![
                "INFO ignoreip: home.example.net now resolves to 203.0.113.7 (was none)",
                "WARNING ignoreip: the look-up of home.example.net failed, the addresses it last \
                 resolved to stay exempt (203.0.113.7): no such name",
            ]
        );
    }

    /// The start of the service names each name and what it resolves to,
    /// and each that does not resolve; nothing without a name.
    #[test]
    fn the_start_says_what_each_name_resolves_to() {
        let fixed = Fixed::new(ip("192.0.2.200"));
        fixed.set_name(VPN, Ok(vec![ip("198.51.100.5")]));
        let ignored = IgnoredNames::new(
            &config(&format!("{} {}", HOME, VPN)),
            Box::new(fixed.clone()),
        );
        capture_log();
        ignored.log_start();
        assert_eq!(
            captured_log(),
            vec![
                "INFO ignoreip names, never banned: home.example.net not resolved, \
                 vpn.example.org 198.51.100.5",
                "WARNING ignoreip: home.example.net does not resolve, so it exempts no address \
                 until it does; it is tried again every 5 min: cannot resolve home.example.net: \
                 no such name",
            ]
        );
        IgnoredNames::new(&config("203.0.113.7"), Box::new(fixed)).log_start();
        assert!(captured_log().is_empty());
    }

    /// The system's resolver, with an address only: no name server is
    /// asked. A name in `ignoreip` is resolved with port 0.
    #[test]
    fn the_port_is_not_used() {
        let mut system = crate::own::System;
        assert_eq!(
            system.resolve("127.0.0.1", 0).unwrap(),
            vec![Ipv4Addr::LOCALHOST]
        );
    }
}
