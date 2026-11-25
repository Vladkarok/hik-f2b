//! Host names resolved now and then, with the last answer kept.
//!
//! A name is resolved at once when it is first asked for, and then at most
//! every `RESOLVE_EVERY` of host time: the resolver may be slow, and a poll
//! must not wait for it each time. A look-up that fails, or finds no IPv4
//! address, keeps the addresses last found, and its reason is given until
//! the next look-up. An IPv4 address written as such needs no look-up.
//!
//! The resolver is passed in with each question, so any caller can use this
//! with its own: `own.rs` asks its `Source`. Like the rest of the engine,
//! the host time is passed in, so the rules can be tested on their own.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

/// The longest time a name's answer is used before it is looked up again:
/// the interval of the firewall check (`health::HEALTH_CHECK_INTERVAL`).
/// An address that moved is then found by the time the next check uses it,
/// and a slow resolver delays at most one poll in ten (at the default
/// `poll_interval` of 30 s).
pub const RESOLVE_EVERY: u64 = 300;

/// When a name was last looked up.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
enum When {
    #[default]
    Never,
    /// Before the host time was known (at startup): the next question that
    /// gives the time sets it.
    Startup,
    /// At this host time.
    At(u64),
}

/// What is known of one name.
#[derive(Clone, Debug, Default, PartialEq)]
struct Name {
    /// The addresses last found (empty if none ever was).
    known: Vec<Ipv4Addr>,
    /// Why the last look-up failed, if it did.
    error: Option<String>,
    at: When,
}

/// The names asked for so far, with their last answers.
#[derive(Debug, Default)]
pub struct Names {
    names: BTreeMap<String, Name>,
}

impl Names {
    pub fn new() -> Names {
        Names::default()
    }

    /// The IPv4 addresses of `host` (a name, or an IPv4 address that is
    /// returned as it is), and why its last look-up failed, if it did.
    ///
    /// `resolve` is called only for a name never asked for, or one last
    /// looked up `RESOLVE_EVERY` or more before `now`, or after `now` (the
    /// host clock went back). `now` is `None` before the host time is known
    /// (at startup): a name never asked for is then looked up, and its time
    /// is set by the next question that gives one.
    pub fn lookup(
        &mut self,
        host: &str,
        now: Option<u64>,
        resolve: impl FnOnce(&str) -> Result<Vec<Ipv4Addr>, String>,
    ) -> (Vec<Ipv4Addr>, Option<String>) {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return (vec![ip], None);
        }
        let name = self.names.entry(host.to_string()).or_default();
        let due = match (name.at, now) {
            (When::Never, _) => true,
            (When::Startup, Some(now)) => {
                name.at = When::At(now);
                false
            }
            (When::Startup, None) | (When::At(_), None) => false,
            (When::At(at), Some(now)) => now < at || now - at >= RESOLVE_EVERY,
        };
        if due {
            name.at = now.map_or(When::Startup, When::At);
            name.error = match resolve(host) {
                Ok(addresses) if !addresses.is_empty() => {
                    name.known = addresses;
                    None
                }
                Ok(_) => Some(format!("{} has no IPv4 address", host)),
                Err(e) => Some(e),
            };
        }
        (name.known.clone(), name.error.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const T0: u64 = 1_768_000_000;

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    /// Asks `names` for `host` at `now` with a resolver that answers
    /// `answer`; also returns whether the resolver was called.
    fn ask(
        names: &mut Names,
        host: &str,
        now: Option<u64>,
        answer: Result<Vec<Ipv4Addr>, String>,
    ) -> (Vec<Ipv4Addr>, Option<String>, bool) {
        let called = Cell::new(false);
        let (known, error) = names.lookup(host, now, |_| {
            called.set(true);
            answer
        });
        (known, error, called.get())
    }

    #[test]
    fn an_address_needs_no_look_up() {
        let mut names = Names::new();
        assert_eq!(
            ask(&mut names, "192.0.2.1", Some(T0), Err("x".into())),
            (vec![ip("192.0.2.1")], None, false)
        );
        assert!(names.names.is_empty());
    }

    #[test]
    fn a_name_is_looked_up_at_once_then_at_most_every_interval() {
        let mut names = Names::new();
        let a = Ok(vec![ip("192.0.2.5")]);
        let b = Ok(vec![ip("192.0.2.6")]);
        assert_eq!(
            ask(&mut names, "nvr.example.net", Some(T0), a.clone()),
            (vec![ip("192.0.2.5")], None, true)
        );
        // within the interval: the last answer, no look-up
        assert_eq!(
            ask(&mut names, "nvr.example.net", Some(T0 + 30), b.clone()),
            (vec![ip("192.0.2.5")], None, false)
        );
        assert_eq!(
            ask(
                &mut names,
                "nvr.example.net",
                Some(T0 + RESOLVE_EVERY - 1),
                b.clone()
            ),
            (vec![ip("192.0.2.5")], None, false)
        );
        // the interval has passed
        assert_eq!(
            ask(
                &mut names,
                "nvr.example.net",
                Some(T0 + RESOLVE_EVERY),
                b.clone()
            ),
            (vec![ip("192.0.2.6")], None, true)
        );
        // counted from that look-up
        assert_eq!(
            ask(
                &mut names,
                "nvr.example.net",
                Some(T0 + 2 * RESOLVE_EVERY - 1),
                a.clone()
            ),
            (vec![ip("192.0.2.6")], None, false)
        );
        // another name is looked up at once
        assert_eq!(
            ask(&mut names, "router.example.net", Some(T0 + 31), a),
            (vec![ip("192.0.2.5")], None, true)
        );
    }

    #[test]
    fn a_failed_look_up_keeps_the_last_answer_until_the_next_one() {
        let mut names = Names::new();
        let host = "nvr.example.net";
        ask(&mut names, host, Some(T0), Ok(vec![ip("192.0.2.5")]));
        let failed = Err("cannot resolve nvr.example.net: timed out".to_string());
        assert_eq!(
            ask(&mut names, host, Some(T0 + RESOLVE_EVERY), failed.clone()),
            (
                vec![ip("192.0.2.5")],
                Some("cannot resolve nvr.example.net: timed out".to_string()),
                true
            )
        );
        // a failure is not looked up again before the interval either, and
        // its reason stays
        let (known, error, called) = ask(
            &mut names,
            host,
            Some(T0 + RESOLVE_EVERY + 30),
            Ok(vec![ip("192.0.2.6")]),
        );
        assert_eq!((known, called), (vec![ip("192.0.2.5")], false));
        assert!(error.is_some());
        // no IPv4 address is a failure too
        assert_eq!(
            ask(&mut names, host, Some(T0 + 2 * RESOLVE_EVERY), Ok(vec![])),
            (
                vec![ip("192.0.2.5")],
                Some("nvr.example.net has no IPv4 address".to_string()),
                true
            )
        );
        // a name that never resolved is tried at every interval, not more
        let never = "gone.example.net";
        assert_eq!(
            ask(&mut names, never, Some(T0), Err("no such name".into())),
            (vec![], Some("no such name".to_string()), true)
        );
        assert!(!ask(&mut names, never, Some(T0 + 30), Err("no such name".into())).2);
        assert!(ask(&mut names, never, Some(T0 + RESOLVE_EVERY), Err("x".into())).2);
    }

    #[test]
    fn at_startup_the_next_question_sets_the_time() {
        let mut names = Names::new();
        let host = "nvr.example.net";
        assert!(ask(&mut names, host, None, Ok(vec![ip("192.0.2.5")])).2);
        // no time yet: the answer stays
        assert!(!ask(&mut names, host, None, Ok(vec![ip("192.0.2.6")])).2);
        // the first poll: counted from now, not looked up again
        assert_eq!(
            ask(&mut names, host, Some(T0), Ok(vec![ip("192.0.2.6")])),
            (vec![ip("192.0.2.5")], None, false)
        );
        assert!(!ask(&mut names, host, Some(T0 + RESOLVE_EVERY - 1), Ok(vec![])).2);
        assert!(
            ask(
                &mut names,
                host,
                Some(T0 + RESOLVE_EVERY),
                Ok(vec![ip("192.0.2.6")])
            )
            .2
        );
    }

    #[test]
    fn a_host_clock_that_went_back_looks_up_again() {
        let mut names = Names::new();
        let host = "nvr.example.net";
        ask(&mut names, host, Some(T0), Ok(vec![ip("192.0.2.5")]));
        assert_eq!(
            ask(&mut names, host, Some(T0 - 3600), Ok(vec![ip("192.0.2.6")])),
            (vec![ip("192.0.2.6")], None, true)
        );
        // and counts from then
        assert!(!ask(&mut names, host, Some(T0 - 3600 + 30), Ok(vec![])).2);
    }
}
