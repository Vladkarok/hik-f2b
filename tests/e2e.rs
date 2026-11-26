//! End-to-end tests against in-process fakes: NVRs (with real digest
//! verification), the RouterOS REST API and the Telegram Bot API. The fakes
//! and the `Harness` are in `support/fake.rs`, shared with `tests/sim.rs`.
//!
//! The host clock is driven by the tests (`Engine::cycle_at`). Each fake
//! NVR's clock is the host clock plus its own `skew`; by default a device
//! shows local time two hours ahead of UTC, as an NVR set to UTC+2 does.

#[path = "support/fake.rs"]
mod fake;
#[path = "support/mmdb.rs"]
mod mmdb;

use fake::*;
use hik_f2b::action::{Firewall, Notifier};
use hik_f2b::state::State;
use hik_f2b::telegram::Telegram;
use hik_f2b::util;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// How many captured log lines are exactly `line` (level and text).
fn exactly(lines: &[String], line: &str) -> usize {
    lines.iter().filter(|l| *l == line).count()
}

/// How many captured log lines start with `prefix`: for a line that ends
/// with an error of the operating system's network stack.
fn starting(lines: &[String], prefix: &str) -> usize {
    lines.iter().filter(|l| l.starts_with(prefix)).count()
}

// ---------------------------------------------------------------- basics

#[test]
fn backlog_before_first_run_is_ignored() {
    let mut h = Harness::raw(false);
    for minute in 10..20 {
        h.add(&format!("09:{}:00", minute), ATTACKER);
    }
    h.tick();
    h.cycle("10:01:00");
    assert!(h.banned().is_empty());
}

/// The first poll reads the `lookback` overlap before its own time and
/// records it as already seen: failed logins from before the start are
/// never counted, the ones after it are.
#[test]
fn failed_logins_just_before_the_start_are_not_counted() {
    let mut h = Harness::raw(false);
    // four inside the overlap (lookback = 120 s) before the first poll
    for clock in ["09:58:30", "09:59:00", "09:59:30", "09:59:59"] {
        h.add(clock, ATTACKER);
    }
    h.burst("09:59", OWNER, 5);
    h.tick(); // the first poll, at 10:00:00
    assert_eq!(h.since("nvr1"), format!("{}10:00:00", DAY));
    assert_eq!(h.fake.lock().unwrap().search_requests, 1);
    // one after the start: counted, and it does not make five
    h.add("10:00:10", ATTACKER);
    h.cycle("10:00:30");
    assert_eq!(h.fails(ATTACKER), 1);
    assert_eq!(h.fails(OWNER), 0);
    run(&mut h, 4, 30);
    assert_eq!(h.fails(ATTACKER), 1);
    assert!(h.banned().is_empty());
    assert_eq!(h.engine.state().ledger.waiting(), 0);
    // five after the start are a ban
    h.burst("10:03", "198.51.100.8", 5);
    h.cycle("10:04:00");
    assert_eq!(h.banned(), vec!["198.51.100.8"]);
}

/// A first poll that cannot read the log leaves the NVR unknown; the next
/// poll starts again from its own time.
#[test]
fn first_poll_that_cannot_read_the_log_is_tried_again() {
    let mut h = Harness::raw(false);
    h.fake.lock().unwrap().poison = Some(format!("{}09:59:00", DAY));
    h.tick();
    assert!(!h.engine.state().cursors.get("nvr1").is_some());
    assert_eq!(
        h.engine.readers()[0].failed_polls(),
        0,
        "no window to skip yet"
    );
    h.fake.lock().unwrap().poison = None;
    h.burst("10:00", ATTACKER, 5); // before the start that succeeds
    h.cycle("10:00:30");
    assert_eq!(h.since("nvr1"), format!("{}10:00:30", DAY));
    run(&mut h, 4, 30);
    assert_eq!(h.fails(ATTACKER), 0);
    assert!(h.banned().is_empty());
    h.burst("10:03", ATTACKER, 5);
    h.cycle("10:04:00");
    assert_eq!(h.banned(), vec![ATTACKER]);
}

#[test]
fn ban_on_fifth_failure() {
    let mut h = Harness::new(false);
    h.add("10:01:00", ATTACKER);
    h.add("10:01:00", ATTACKER); // same second, same user: still two failures
    h.add_full("10:02:00", ATTACKER, "illegal usernam", "illlegealAccess");
    h.add("10:04:30", ATTACKER);
    h.cycle("10:05:00");
    h.cycle("10:05:30"); // the overlapping window must not be counted twice
    assert!(h.banned().is_empty());
    assert_eq!(h.engine.state().ledger.failed_logins(attacker()), 4);

    h.add("10:06:00", ATTACKER);
    h.cycle("10:06:30");
    assert_eq!(h.banned(), vec![ATTACKER]);
    let body = h.fake.lock().unwrap().ban_bodies[0].clone();
    assert!(body.contains("\"list\":\"cctv_ban\""), "{}", body);
    assert!(body.contains("\"timeout\":\"1d00:00:00\""), "{}", body);
    // the comment carries the host (UTC) time of the failure
    assert!(
        body.contains("hik-f2b nvr1 user=admin 2026-01-10T08:06:00Z"),
        "{}",
        body
    );
    assert_eq!(h.engine.state().ledger.sizes().tracked, 0);
    assert_eq!(h.engine.state().ledger.waiting(), 0);
}

#[test]
fn occasional_typos_are_not_banned() {
    let mut h = Harness::new(false);
    for clock in [
        "10:06:10", "10:40:00", "11:20:00", "12:10:00", "12:59:00", "13:50:00",
    ] {
        h.add(clock, OWNER);
    }
    h.cycle("14:00:00");
    assert!(h.banned().is_empty());
}

#[test]
fn ignored_addresses_and_unrelated_entries() {
    let mut h = Harness::new(false);
    for second in 10..20 {
        h.add(&format!("10:01:{}", second), "192.168.1.50");
        h.add(&format!("10:01:{}", second), "127.0.0.1");
        h.add_full(&format!("10:01:{}", second), ATTACKER, "", "videoLost/30");
        h.add_full(
            &format!("10:01:{}", second),
            "not-an-address",
            "admin",
            "illlegealAccess",
        );
        h.add_full(
            &format!("10:01:{}", second),
            "::",
            "admin",
            "illlegealAccess",
        );
    }
    h.cycle("10:02:00");
    assert!(h.banned().is_empty());
    assert_eq!(h.engine.state().ledger.sizes().tracked, 0);
}

#[test]
fn many_entries_are_paged() {
    for newest_first in [false, true] {
        let mut h = Harness::new(false);
        h.fake.lock().unwrap().newest_first = newest_first;
        for i in 0..250 {
            h.add(&format!("10:{:02}:{:02}", 1 + i / 60, i % 60), ATTACKER);
        }
        h.cycle("10:10:00");
        assert_eq!(h.banned(), vec![ATTACKER]);
        assert!(h.fake.lock().unwrap().search_requests >= 4);
        assert_eq!(h.since("nvr1"), format!("{}10:05:09", DAY));
    }
}

#[test]
fn ban_is_retried_when_router_is_down() {
    let mut h = Harness::new(false);
    h.fake.lock().unwrap().router_down = true;
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert!(h.banned().is_empty());
    assert_eq!(h.engine.state().ledger.waiting(), 1);
    h.fake.lock().unwrap().router_down = false;
    h.cycle("10:02:30");
    assert_eq!(h.banned(), vec![ATTACKER]);
    assert_eq!(h.engine.state().ledger.waiting(), 0);
}

/// A waiting ban is checked against `ignoreip` again before it is applied:
/// an owner who adds their address and restarts is not banned when the
/// router is back.
#[test]
fn waiting_ban_of_an_address_now_in_ignoreip_is_dropped() {
    const NEIGHBOUR: &str = "203.0.113.21";
    let mut h = Harness::new(false);
    h.fake.lock().unwrap().router_unreachable = true;
    h.burst("10:01", OWNER, 5);
    h.burst("10:01", ATTACKER, 5);
    h.add("10:01:30", NEIGHBOUR);
    h.cycle("10:02:00");
    assert!(h.engine.state().ledger.is_waiting(ip(OWNER)));
    assert!(h.engine.state().ledger.is_waiting(attacker()));
    assert_eq!(h.fails(NEIGHBOUR), 1);

    // OWNER and NEIGHBOUR are in 203.0.113.16/29
    h.ini = h
        .ini
        .replace("[general]\n", "[general]\nignoreip = 203.0.113.16/29\n");
    util::capture_log();
    h.restart();
    let log = util::captured_log();
    assert_eq!(
        logged(
            &log,
            "INFO 203.0.113.20: waiting ban dropped, 5 counted failed login(s) forgotten: the \
             address is in ignoreip or a reserved range and is never banned"
        ),
        1,
        "{:?}",
        log
    );
    assert_eq!(
        logged(
            &log,
            "INFO 203.0.113.21: 1 counted failed login(s) forgotten: "
        ),
        1,
        "{:?}",
        log
    );
    assert!(!h.engine.state().ledger.is_waiting(ip(OWNER)));
    assert_eq!(h.fails(OWNER), 0);
    assert_eq!(h.fails(NEIGHBOUR), 0);

    h.fake.lock().unwrap().router_unreachable = false;
    h.advance(30);
    assert_eq!(h.banned(), vec![ATTACKER], "no ban request for the owner");
    assert_eq!(h.engine.state().ledger.waiting(), 0);
    assert!(h.fake.lock().unwrap().lookups.is_empty());
    let path = h.dir.join("state");
    h.engine.state().save(&path).unwrap();
    let saved = std::fs::read_to_string(&path).unwrap();
    assert!(!saved.contains(OWNER), "{}", saved);
}

#[test]
fn manual_unban_allows_a_new_ban() {
    let mut h = Harness::new(false);
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    h.fake.lock().unwrap().bans.clear(); // an admin removed the entry on the router
    h.burst("10:30", ATTACKER, 5);
    h.cycle("10:31:00");
    assert_eq!(h.banned(), vec![ATTACKER]);
}

#[test]
fn rejected_nvr_login_backs_off_after_one_attempt() {
    let mut h = Harness::new(false);
    h.fake.lock().unwrap().nvr_auth_ok = false;
    util::capture_log();
    h.cycle("10:01:00");
    assert!(h.engine.readers()[0].retry_after() > 0);
    // exactly one refused login, so the NVR's own lock is not provoked
    assert_eq!(h.fake.lock().unwrap().refused_logins, 1);
    // what the operator is told to check
    let log = util::captured_log();
    assert_eq!(
        exactly(
            &log,
            "ERROR nvr1: login to the NVR was rejected (HTTP 401). Check the user, the password \
             and the 'Remote: Log Search' permission. Next try in 900 s."
        ),
        1,
        "{:?}",
        log
    );
    h.fake.lock().unwrap().nvr_auth_ok = true;
    let before = h.fake.lock().unwrap().search_requests;
    h.cycle("10:01:30"); // still backing off: the NVR is not contacted
    assert_eq!(h.fake.lock().unwrap().search_requests, before);
    assert_eq!(h.fake.lock().unwrap().refused_logins, 1);
    assert_eq!(logged(&util::captured_log(), "login to the NVR"), 0);
    // after auth_backoff (900 s) it is contacted again
    h.cycle("10:16:30");
    assert!(h.fake.lock().unwrap().search_requests > before);
}

#[test]
fn host_clock_jumping_back_does_not_stall_the_backoff() {
    let mut h = Harness::new(false);
    h.fake.lock().unwrap().nvr_auth_ok = false;
    h.cycle("10:01:00");
    assert!(h.engine.readers()[0].retry_after() > 0);
    h.fake.lock().unwrap().nvr_auth_ok = true;
    let before = h.fake.lock().unwrap().search_requests;
    // the host clock is set back a year; the device clock stays right
    h.fake.lock().unwrap().skew += 365 * 86400;
    h.set_host(h.host - 365 * 86400 + 30);
    h.tick();
    assert!(
        h.fake.lock().unwrap().search_requests > before,
        "a backoff of a year must count as expired"
    );
}

#[test]
fn dry_run_does_not_touch_the_router() {
    let mut h = Harness::with(Opts {
        telegram: true,
        general: "dry_run = true",
        ..Default::default()
    });
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert!(h.banned().is_empty());
    assert!(h.engine.state().ledger.banned_until(attacker()).is_some());
    let sent = h.fake.lock().unwrap().tg_sent.clone();
    assert_eq!(sent.len(), 1);
    let text = text_of(&sent[0]);
    assert!(
        text.contains("198.51.100.7 would be banned for 1d00:00:00 (dry run)"),
        "{}",
        text
    );
    assert!(!text.contains("[dry run"), "{}", text);
}

#[test]
fn hostile_user_name_cannot_inject_anything() {
    let mut h = Harness::new(true);
    // After XML decoding the user name is:  x",<newline>"list":"evil
    let user = "x&quot;,&#10;&quot;list&quot;:&quot;evil";
    for second in 10..15 {
        h.add_full(
            &format!("10:01:{}", second),
            ATTACKER,
            user,
            "illlegealAccess",
        );
    }
    h.cycle("10:02:00");
    assert_eq!(h.banned(), vec![ATTACKER]);
    let body = h.fake.lock().unwrap().ban_bodies[0].clone();
    assert!(!body.contains('\n'), "raw newline in request: {}", body);
    assert!(body.contains(r#"user=x\",?\"list\":\"evil "#), "{}", body);
    assert!(
        body.starts_with("{\"list\":\"cctv_ban\",\"address\":\"198.51.100.7\","),
        "{}",
        body
    );

    // Telegram form body: the name is one line of the text, nothing more
    let sent = h.fake.lock().unwrap().tg_sent.clone();
    assert_eq!(sent.len(), 1);
    assert!(
        !sent[0].contains('\n') && !sent[0].contains('"'),
        "{}",
        sent[0]
    );
    let fields = form(&sent[0]);
    let keys: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        keys,
        vec!["chat_id", "text", "message_thread_id"],
        "{}",
        sent[0]
    );
    let text = text_of(&sent[0]);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 4, "{:?}", lines);
    assert_eq!(lines[2], "User tried: x\",?\"list\":\"evil");
    assert_eq!(
        lines[0],
        "\u{26d4} hik-f2b: 198.51.100.7 banned for 1d00:00:00"
    );
}

/// A user name is cut to the same length whether it is counted from the
/// NVR log or read back from a waiting ban in the state file.
#[test]
fn a_long_user_name_is_cut_alike_when_counted_and_when_loaded() {
    let mut h = Harness::new(false);
    let long = "abcdefghij".repeat(5);
    h.fake.lock().unwrap().router_unreachable = true; // the ban waits
    for second in 10..15 {
        h.add_full(
            &format!("10:01:{}", second),
            ATTACKER,
            &long,
            "illlegealAccess",
        );
    }
    h.cycle("10:02:00");
    assert_eq!(h.engine.state().ledger.waiting(), 1);
    let saved = h.engine.state().serialize();
    let line = saved
        .lines()
        .find(|line| line.starts_with("pending "))
        .unwrap()
        .to_string();
    assert!(
        line.ends_with(&format!(" nvr1 {}", &long[..32])),
        "{}",
        line
    );
    // the same waiting ban with the whole user name in the state file
    let whole = saved.replace(&line, &format!("{}{}", line, &long[32..]));
    assert_ne!(whole, saved);
    assert_eq!(State::parse(&whole), *h.engine.state());
}

#[test]
fn ban_rate_limit_holds_back_a_flood() {
    let mut h = Harness::with(Opts {
        general: "max_bans_per_hour = 2",
        ..Default::default()
    });
    for ip in ["198.51.100.1", "198.51.100.2", "198.51.100.3"] {
        h.burst("10:01", ip, 5);
    }
    h.cycle("10:02:00");
    assert_eq!(h.banned().len(), 2);
    assert_eq!(h.engine.state().ledger.waiting(), 1);
}

#[test]
fn telegram_notification_goes_to_the_topic() {
    let mut h = Harness::new(true);
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert_eq!(h.banned(), vec![ATTACKER]);
    let sent = h.fake.lock().unwrap().tg_sent.clone();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].contains("chat_id=-1001234567890"), "{}", sent[0]);
    assert!(sent[0].contains("message_thread_id=42"), "{}", sent[0]);
    assert!(sent[0].contains("198.51.100.7"), "{}", sent[0]);
    assert!(!sent[0].contains("parse_mode"), "{}", sent[0]);
    // an address that is already listed is not announced again
    h.burst("10:20", ATTACKER, 5);
    h.cycle("10:21:00");
    assert_eq!(h.fake.lock().unwrap().tg_sent.len(), 1);
}

#[test]
fn telegram_outage_does_not_block_bans_and_is_retried() {
    let mut h = Harness::new(true);
    h.fake.lock().unwrap().tg_fail = true;
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert_eq!(
        h.banned(),
        vec![ATTACKER],
        "the ban must not wait for Telegram"
    );
    assert_eq!(h.engine.queued_notifications(), 1);
    h.fake.lock().unwrap().tg_fail = false;
    h.cycle("10:02:30");
    assert_eq!(h.fake.lock().unwrap().tg_sent.len(), 1);
    assert_eq!(h.engine.queued_notifications(), 0);
}

/// Telegram's rate limit (HTTP 429 with `retry_after`): nothing is sent
/// until the wait is over, the wait costs no attempt, and the rest of the
/// queue goes out afterwards.
#[test]
fn telegram_rate_limit_is_waited_out() {
    let mut h = Harness::with(Opts {
        telegram: true,
        general: "max_bans_per_hour = 100",
        ..Default::default()
    });
    util::capture_log();
    h.fake.lock().unwrap().tg_accept = Some(20);
    for n in 1..=30 {
        h.burst("10:01", &format!("198.51.100.{}", n), 5);
    }
    h.cycle("10:02:00");
    assert_eq!(h.banned().len(), 30);
    {
        let f = h.fake.lock().unwrap();
        assert_eq!(f.tg_sent.len(), 20);
        assert_eq!(f.tg_attempts, 21, "the queue stops at the first 429");
    }
    assert_eq!(h.engine.queued_notifications(), 10);
    // within retry_after (30 s): not a single request
    h.advance(20);
    assert_eq!(h.fake.lock().unwrap().tg_attempts, 21);
    // after it: the rest, none dropped
    h.fake.lock().unwrap().tg_accept = None;
    h.advance(10);
    let f = h.fake.lock().unwrap();
    assert_eq!(f.tg_sent.len(), 30);
    assert_eq!(f.tg_attempts, 31);
    drop(f);
    assert_eq!(h.engine.queued_notifications(), 0);
    let log = util::captured_log();
    assert_eq!(
        logged(&log, "Telegram asks to wait 30 s before the next message"),
        1
    );
    assert_eq!(
        logged(&log, "notification failed"),
        0,
        "a 429 is not an outage"
    );
}

/// A full queue drops new notifications, with one WARNING per poll that
/// counts them.
#[test]
fn dropped_notifications_are_logged() {
    let mut h = Harness::with(Opts {
        telegram: true,
        general: "max_bans_per_hour = 200",
        ..Default::default()
    });
    util::capture_log();
    h.fake.lock().unwrap().tg_fail = true;
    for n in 1..=105 {
        let address = if n <= 100 {
            format!("198.51.100.{}", n)
        } else {
            format!("203.0.113.{}", n - 100)
        };
        h.burst("10:01", &address, 5);
    }
    h.cycle("10:02:00");
    assert_eq!(h.banned().len(), 105);
    assert_eq!(h.engine.queued_notifications(), 100);
    let log = util::captured_log();
    assert_eq!(
        logged(
            &log,
            "WARNING 5 notification(s) dropped: 100 already wait to be sent"
        ),
        1,
        "{:?}",
        log.iter()
            .filter(|l| l.contains("dropped"))
            .collect::<Vec<_>>()
    );
    h.advance(30);
    assert_eq!(logged(&util::captured_log(), "dropped:"), 0);
}

#[test]
fn telegram_errors_never_reveal_the_token() {
    let h = Harness::new(true);
    h.fake.lock().unwrap().tg_fail = true;
    let err = Telegram::new(h.config().telegram.as_ref().unwrap())
        .unwrap()
        .send("x")
        .unwrap_err()
        .to_string();
    assert!(!err.contains(TOKEN), "{}", err);
    assert!(err.contains("<token>"), "{}", err);
}

#[test]
fn state_survives_a_restart() {
    let mut h = Harness::new(false);
    h.burst("10:01", ATTACKER, 4);
    h.cycle("10:02:00");
    let path = h.dir.join("state");
    h.engine.state().save(&path).unwrap();
    let restored = State::load(&path).unwrap();
    assert_eq!(&restored, h.engine.state());
    assert_eq!(restored.ledger.failed_logins(attacker()), 4);
}

// ---------------------------------------------------------- device clocks

/// C1: the device clock goes back one hour (DST ends) mid-run.
#[test]
fn dst_fall_back() {
    let mut h = Harness::new(false);
    // typos spread over the hour before the change; by 11:01 the read
    // window has moved past the first two
    h.add("10:30:10", OWNER);
    h.cycle("10:31:00");
    h.add("10:45:10", OWNER);
    h.cycle("10:46:00");
    h.add("11:00:10", OWNER);
    h.cycle("11:01:00");
    assert_eq!(h.fails(OWNER), 3);

    // 11:05 local becomes 10:05 again
    h.fake.lock().unwrap().skew = SKEW - 3600;
    h.set_host(host_of("11:05:00"));
    assert_eq!(h.fake.lock().unwrap().now, format!("{}10:05:00", DAY));
    h.tick();
    // the entries before the jump now look like they are in the future;
    // they are already counted and must not be counted again
    assert_eq!(h.fails(OWNER), 3);
    assert_eq!(h.since("nvr1"), format!("{}10:05:00", DAY));

    // a brute-forcer after the jump, logged with the repeated hour
    h.burst("10:06", ATTACKER, 5);
    h.advance(90);
    assert_eq!(h.banned(), vec![ATTACKER]);
    for _ in 0..5 {
        h.advance(30);
    }
    assert_eq!(h.fails(OWNER), 3, "failures before the jump counted twice");
    // the owner's 4th typo after the jump is counted normally
    h.add("10:09:10", OWNER);
    h.advance(30);
    assert_eq!(h.fails(OWNER), 4);
    assert_eq!(h.banned(), vec![ATTACKER]);
}

/// DST ends on a quiet NVR while it cannot be reached. Its read position
/// trails its clock by `findtime + lookback`, so after the step the clock is
/// still ahead of it, and only the offset (one hour less) shows the step.
/// Failed logins logged before the step and read after it must not be
/// converted with the new offset (an hour later than they happened).
#[test]
fn dst_end_on_a_quiet_nvr_after_an_outage_is_a_resync() {
    let mut h = Harness::new(false);
    util::capture_log();
    run(&mut h, 3, 30);
    // the NVR goes away; an attacker is logged at the start of the outage
    h.fake.lock().unwrap().nvr_down = true;
    let down = h.host;
    for i in 0..5 {
        Harness::add_at(&h.fake, &device(down + 10 + i + SKEW), ATTACKER);
    }
    run(&mut h, 13, 300);
    // an hour later DST has ended, and the NVR is back
    h.fake.lock().unwrap().skew = SKEW - 3600;
    h.fake.lock().unwrap().nvr_down = false;
    h.advance(300);
    let log = util::captured_log();
    assert_eq!(
        logged(&log, "nvr1: device clock jumped back by 3600 s"),
        1,
        "{:?}",
        log
    );
    // the old entries are recorded as seen, not counted an hour late
    assert_eq!(h.fails(ATTACKER), 0);
    assert_eq!(h.engine.state().ledger.waiting(), 0);
    assert!(h.banned().is_empty());
    assert_eq!(h.engine.state().cursors["nvr1"].offset(), Some(SKEW - 3600));
    // after the step, failed logins count as usual
    let now = h.host;
    for i in 0..5 {
        Harness::add_at(&h.fake, &device(now + 5 + i + SKEW - 3600), ATTACKER);
    }
    h.advance(30);
    assert_eq!(h.banned(), vec![ATTACKER]);
    // a change of 15 minutes or less is no jump, in either direction
    for step in [-900, 900] {
        let skew = h.fake.lock().unwrap().skew;
        h.fake.lock().unwrap().skew = skew + step;
        h.advance(30);
        assert_eq!(logged(&util::captured_log(), "device clock jumped"), 0);
    }
}

/// A device clock that ran 400 s fast is corrected (more than lookback, less
/// than an hour). Entries from the minutes before the correction come back
/// into the read window with times only slightly in the future; only the
/// resync baseline keeps them from being counted again.
#[test]
fn small_backward_correction_is_not_recounted() {
    let mut h = Harness::new(false);
    h.add("10:01:10", OWNER);
    h.add("10:02:10", OWNER);
    h.cycle("10:03:00");
    h.add("10:05:30", OWNER);
    h.cycle("10:06:00");
    h.cycle("10:06:30"); // the window now starts after the first two
    assert_eq!(h.fails(OWNER), 3);

    h.fake.lock().unwrap().skew = SKEW - 400;
    h.set_host(host_of("10:07:00"));
    assert_eq!(h.fake.lock().unwrap().now, format!("{}10:00:20", DAY));
    h.tick();
    for _ in 0..4 {
        h.advance(30);
    }
    assert_eq!(
        h.fails(OWNER),
        3,
        "entries before the correction counted twice"
    );
    assert!(h.banned().is_empty());
}

/// Found by `tests/sim.rs` (Clock class). A backward correction smaller than
/// `lookback` used to move the read cursor back to the new device time
/// without a resync, so the next window started before the previous one:
/// entries in between were no longer in `seen` and were counted a second
/// time. A device clock behind the cursor now always resyncs.
#[test]
fn small_backward_correction_below_lookback_is_not_recounted() {
    let mut h = Harness::new(false); // first poll at 10:00:00 (device)
    h.add("10:01:00", OWNER);
    h.cycle("10:01:30");
    h.add("10:03:20", OWNER);
    h.cycle("10:03:30");
    // the window now starts at 10:01:20: the first typo has left it
    h.cycle("10:04:00");
    assert_eq!(h.fails(OWNER), 2);

    // the device clock is corrected back by 100 s: 10:04:30 shows 10:02:50
    h.fake.lock().unwrap().skew = SKEW - 100;
    h.set_host(host_of("10:04:30"));
    assert_eq!(h.fake.lock().unwrap().now, format!("{}10:02:50", DAY));
    h.tick();
    assert_eq!(h.since("nvr1"), format!("{}10:02:50", DAY), "resynced");
    h.advance(30);
    h.advance(30);
    assert_eq!(h.fails(OWNER), 2, "the typo at 10:01:00 was counted twice");
    // failed logins after the correction are counted
    h.burst("10:04", ATTACKER, 5);
    h.advance(60);
    assert_eq!(h.banned(), vec![ATTACKER]);
}

/// Found by `tests/sim.rs` (Clock class). DST ends while the NVR's log
/// cannot be read. The jump is noticed, but the polls fail, and after ten
/// of them the unreadable window is skipped. The skip used to set the
/// cursor and the offset to the new clock without a resync, so the next
/// read saw no jump and counted entries from about an hour before the
/// change (device times of the repeated hour) again. Now the skip clears
/// the offset, and the next read resyncs.
#[test]
fn clock_change_while_the_log_is_unreadable_is_not_recounted() {
    let mut h = Harness::new(false); // first poll at 10:00:00 (device)
    h.add("10:05:10", OWNER);
    h.add("10:05:20", OWNER);
    h.cycle("10:06:00");
    h.add("10:50:00", ATTACKER);
    h.cycle("10:51:00");
    // the window now starts at 10:48:00: the typos have left it
    h.cycle("10:51:30");
    assert_eq!(h.fails(OWNER), 2);

    // 11:00 local becomes 10:00 again, and every log search fails
    {
        let mut f = h.fake.lock().unwrap();
        f.skew = SKEW - 3600;
        f.garbage = true;
    }
    h.set_host(host_of("11:00:00"));
    assert_eq!(h.fake.lock().unwrap().now, format!("{}10:00:00", DAY));
    h.tick();
    run(&mut h, 9, 30); // the 10th failure skips the window
    assert_eq!(h.since("nvr1"), format!("{}10:04:30", DAY));
    assert_eq!(
        h.engine.state().cursors["nvr1"].offset(),
        None,
        "a resync is still due"
    );
    // the resync that is due survives a restart (`-` in the state file)
    h.restart();
    h.fake.lock().unwrap().garbage = false;
    h.advance(30);
    assert_eq!(h.fails(OWNER), 2, "the typos at 10:05 were counted twice");
    assert_eq!(h.engine.state().cursors["nvr1"].offset(), Some(SKEW - 3600));
    // failed logins after the resync are counted
    h.burst("10:06", ATTACKER, 5);
    h.cycle("11:07:00");
    assert_eq!(h.banned(), vec![ATTACKER]);
}

/// C2: the RTC is reset to 2000-01-01 (power cut) and later corrected.
#[test]
fn rtc_reset_and_recovery() {
    let mut h = Harness::new(false);
    for second in 10..14 {
        h.add(&format!("10:01:{}", second), OWNER);
    }
    h.cycle("10:02:00");
    assert_eq!(h.fails(OWNER), 4);

    let host = host_of("10:05:00");
    let reset = util::parse_ts("2000-01-01T00:00:00").unwrap();
    h.fake.lock().unwrap().skew = reset - host;
    h.set_host(host);
    h.tick();
    assert_eq!(h.since("nvr1"), "2000-01-01T00:00:00");

    // while the clock is wrong a brute-forcer is still caught: its times
    // are converted with the device's current offset
    let fake = Arc::clone(&h.fake);
    for second in 10..15 {
        Harness::add_at(&fake, &format!("2000-01-01T00:01:{}", second), ATTACKER);
    }
    h.advance(90);
    assert_eq!(h.banned(), vec![ATTACKER]);

    // NTP corrects the clock 15 minutes later: the old 10:01 entries come
    // back into view and must not be counted again
    h.fake.lock().unwrap().skew = SKEW;
    h.cycle("10:20:00");
    for _ in 0..4 {
        h.advance(30);
    }
    assert_eq!(h.fails(OWNER), 4, "old history counted again");
    assert_eq!(h.banned(), vec![ATTACKER]);

    // a new brute-forcer after the recovery is banned
    h.burst("10:23", "198.51.100.8", 5);
    h.cycle("10:24:00");
    assert_eq!(h.banned(), vec![ATTACKER, "198.51.100.8"]);
}

/// The device clock is far behind for a long time (or the daemon was down):
/// the next poll does not read the whole history.
#[test]
fn long_gap_reads_only_findtime() {
    let mut h = Harness::new(false);
    // entries during a 5 hour outage of the daemon
    h.add("11:00:10", OWNER);
    h.burst("14:30", "198.51.100.9", 5);
    h.cycle("15:00:00");
    assert_eq!(h.fails(OWNER), 0, "older than findtime");
    assert_eq!(h.banned(), vec!["198.51.100.9"]);
}

/// C3: two NVRs whose clocks are two hours apart count together.
#[test]
fn two_nvrs_with_different_clocks() {
    let mut h = Harness::build(Opts {
        second_nvr: true,
        ..Default::default()
    });
    let slow = h.fake2.clone().unwrap();
    // nvr2 is set to UTC: two hours behind nvr1
    slow.lock().unwrap().skew = 0;
    h.tick();
    assert_eq!(h.fake.lock().unwrap().now, format!("{}10:00:00", DAY));
    assert_eq!(slow.lock().unwrap().now, format!("{}08:00:00", DAY));

    Harness::add_at(&slow, &format!("{}08:01:10", DAY), ATTACKER);
    h.cycle("10:02:00");
    assert_eq!(h.fails(ATTACKER), 1);
    for _ in 0..4 {
        h.advance(30);
        assert_eq!(h.fails(ATTACKER), 1, "slow NVR's counter was erased");
    }
    h.burst("10:04", ATTACKER, 4);
    h.cycle("10:05:00");
    assert_eq!(h.banned(), vec![ATTACKER]);
    let body = h.fake.lock().unwrap().ban_bodies[0].clone();
    assert!(body.contains("2026-01-10T08:04:13Z"), "{}", body);
}

// ------------------------------------------------------- hostile log data

/// C4: undecodable bytes and control characters in user names.
#[test]
fn broken_items_do_not_blind_the_daemon() {
    let mut h = Harness::new(false);
    let fake = Arc::clone(&h.fake);
    h.burst("10:01", ATTACKER, 5);
    let at = |s: &str| format!("{}10:01:{}", DAY, s);
    Harness::entry_to(
        &fake,
        &at("20"),
        "198.51.100.50",
        b"ad\xffmin",
        "illlegealAccess",
    );
    Harness::entry_to(
        &fake,
        &at("21"),
        "198.51.100.51",
        b"ad\x01min",
        "illlegealAccess",
    );
    // an unescaped & would break the XML document itself: read as text
    Harness::entry_to(
        &fake,
        &at("22"),
        "198.51.100.52",
        b"a & b",
        "illlegealAccess",
    );
    // an unescaped < cannot be read safely: skipped with a warning
    Harness::entry_to(&fake, &at("23"), "198.51.100.53", b"a<b", "illlegealAccess");
    util::capture_log();
    h.cycle("10:02:00");
    assert_eq!(h.banned(), vec![ATTACKER]);
    assert_eq!(h.fails("198.51.100.50"), 1);
    assert_eq!(h.fails("198.51.100.51"), 1);
    assert_eq!(h.fails("198.51.100.52"), 1, "a bare & is text");
    assert_eq!(h.fails("198.51.100.53"), 0, "unparseable item is skipped");
    assert_eq!(
        logged(
            &util::captured_log(),
            "WARNING nvr1: 1 log entry could not be parsed and was skipped"
        ),
        1
    );
    // the newest entry that could be read
    assert_eq!(h.since("nvr1"), at("22"));

    // the next poll still sees the broken entries in its overlap, works,
    // and counts nothing twice
    h.add("10:02:10", "198.51.100.60");
    h.cycle("10:02:30");
    assert_eq!(h.fails("198.51.100.60"), 1);
    assert_eq!(h.fails("198.51.100.50"), 1);
    assert_eq!(h.fails("198.51.100.51"), 1);
    assert_eq!(h.fails("198.51.100.52"), 1);
    assert_eq!(h.since("nvr1"), format!("{}10:02:10", DAY));
}

/// C5: a page that cannot be parsed at all, again and again.
#[test]
fn unreadable_log_window_is_skipped_after_ten_polls() {
    let mut h = Harness::new(false);
    h.fake.lock().unwrap().poison = Some(format!("{}10:00:30", DAY));
    for i in 0..9 {
        h.advance(30);
        assert_eq!(h.engine.readers()[0].failed_polls(), i + 1);
        assert_eq!(h.since("nvr1"), format!("{}10:00:00", DAY));
    }
    h.advance(30); // the 10th failure
    assert_eq!(h.since("nvr1"), format!("{}10:05:00", DAY));
    // the clock did not change: no resync, so what follows is counted
    assert_eq!(h.engine.state().cursors["nvr1"].offset(), Some(SKEW));
    assert_eq!(h.engine.readers()[0].failed_polls(), 0);
    assert_eq!(
        h.engine.readers()[0].retry_after(),
        0,
        "not an auth problem"
    );

    h.burst("10:05", ATTACKER, 5);
    h.cycle("10:06:00");
    assert_eq!(h.banned(), vec![ATTACKER]);
}

/// A reply cut off in the middle of an item (hand-written page).
#[test]
fn cut_off_reply_is_salvaged() {
    let mut h = Harness::new(false);
    let item = |ts: &str| {
        format!(
            "<searchMatchItem><logDescriptor><metaId>log.hikvision.com/Exception/illlegealAccess\
             </metaId><StartDateTime>{}{}Z</StartDateTime><userName>admin</userName>\
             <ipAddress>{}</ipAddress></logDescriptor></searchMatchItem>\n",
            DAY, ts, ATTACKER
        )
    };
    let page = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<CMSearchResult><responseStatusStrg>OK\
         </responseStatusStrg><matchList>\n{}{}<searchMatchItem><logDesc",
        item("10:01:10"),
        item("10:01:11")
    );
    h.fake
        .lock()
        .unwrap()
        .raw_pages
        .push_back(page.into_bytes());
    h.cycle("10:02:00");
    assert_eq!(h.fails(ATTACKER), 2);
    assert_eq!(h.since("nvr1"), format!("{}10:01:11", DAY));
}

/// C6: an empty address field and an address typed as the user name.
#[test]
fn address_typed_as_user_name_is_not_used() {
    let mut h = Harness::new(false);
    for second in 10..20 {
        h.add_full(
            &format!("10:01:{}", second),
            "",
            "203.0.113.99",
            "illlegealAccess",
        );
    }
    h.cycle("10:02:00");
    h.cycle("10:02:30");
    assert!(h.banned().is_empty());
    assert_eq!(h.engine.state().ledger.sizes().tracked, 0);
    assert_eq!(h.engine.state().ledger.waiting(), 0);
}

/// Firmware that copies the login name into its log without escaping `<`:
/// markup typed as a user name must not put a victim's address on the list.
#[test]
fn markup_injected_as_user_name_cannot_target_a_victim() {
    const VICTIM: &str = "203.0.113.9";
    let mut h = Harness::new(false);
    // closes <userName>, adds an address, reopens <userName>: ambiguous
    let sibling = format!("a</userName><ipAddress>{}</ipAddress><userName>b", VICTIM);
    for second in 10..15 {
        h.add_full(
            &format!("10:01:{}", second),
            ATTACKER,
            &sibling,
            "illlegealAccess",
        );
    }
    h.cycle("10:02:00");
    h.cycle("10:02:30");
    assert!(h.banned().is_empty());
    assert!(
        h.engine.state().ledger.sizes().tracked == 0,
        "ambiguous entries are not counted"
    );

    // an address nested inside <userName>: the entry counts for the sender
    let nested = format!("a<ipAddress>{}</ipAddress>", VICTIM);
    for second in 10..15 {
        h.add_full(
            &format!("10:03:{}", second),
            ATTACKER,
            &nested,
            "illlegealAccess",
        );
    }
    h.cycle("10:04:00");
    assert_eq!(h.banned(), vec![ATTACKER]);
    let body = h.fake.lock().unwrap().ban_bodies[0].clone();
    assert!(body.contains("user=a203.0.113.9 "), "{}", body);
    h.cycle("10:04:30");
    assert_eq!(h.fails(VICTIM), 0);
    assert!(!h.banned().contains(&VICTIM.to_string()));
    assert_eq!(h.engine.state().ledger.waiting(), 0);
}

/// C7: IPv4-mapped IPv6 in the address field.
#[test]
fn mapped_ipv6_address_is_counted_as_ipv4() {
    let mut h = Harness::new(false);
    h.burst("10:01", "::ffff:198.51.100.7", 5);
    h.cycle("10:02:00");
    assert_eq!(h.banned(), vec![ATTACKER]);
}

/// C15: firmware that ignores the search position.
#[test]
fn identical_page_stops_paging() {
    let mut h = Harness::new(false);
    h.fake.lock().unwrap().stuck_paging = true;
    h.add("10:01:10", OWNER);
    let before = h.fake.lock().unwrap().search_requests;
    util::capture_log();
    h.cycle("10:02:00");
    // the page, the same page again (the search is not complete), and a
    // search of the time before that second, which holds nothing
    assert_eq!(h.fake.lock().unwrap().search_requests - before, 3);
    let log = util::captured_log();
    assert_eq!(
        exactly(
            &log,
            "WARNING nvr1: the NVR returned the same result page twice; it seems to ignore the \
             search position, so this search stops after that page"
        ),
        1,
        "{:?}",
        log
    );
    assert_eq!(h.fails(OWNER), 1);
    h.cycle("10:02:30");
    assert_eq!(h.fails(OWNER), 1);
    assert!(h.banned().is_empty());
}

/// An NVR that ignores the search position and lists newest first: its
/// first page holds the newest entries only. The search is not complete,
/// so the older part is read with narrower searches in the same poll.
#[test]
fn ignored_position_newest_first_reads_the_older_part() {
    let mut h = Harness::new(false);
    {
        let mut f = h.fake.lock().unwrap();
        f.stuck_paging = true;
        f.newest_first = true;
    }
    // the oldest, then more than a page of newer entries (ignoreip)
    h.burst("10:01", ATTACKER, 5);
    let start = util::parse_ts(&format!("{}10:02:00", DAY)).unwrap();
    for n in 0..100 {
        Harness::add_at(&h.fake, &device(start + n), "192.168.1.50");
    }
    util::capture_log();
    h.cycle("10:04:00");
    let log = util::captured_log();
    assert_eq!(
        exactly(
            &log,
            &format!(
                "WARNING nvr1: more log entries within one second ({}10:01:10Z, device time) \
                 than one search can read; some entries of that second may have been skipped",
                DAY
            )
        ),
        1,
        "{:?}",
        log
    );
    assert_eq!(h.fails(ATTACKER), 0, "banned, so no longer counted");
    assert_eq!(h.banned(), vec![ATTACKER]);
    assert_eq!(h.since("nvr1"), format!("{}10:03:39", DAY));
    // the next polls count nothing twice
    run(&mut h, 3, 30);
    assert_eq!(h.banned(), vec![ATTACKER]);
    assert_eq!(h.engine.state().ledger.sizes().tracked, 0);
}

/// A paging status with a namespace prefix is read; a page without one is
/// not taken for the last page.
#[test]
fn paging_status_with_prefix_or_missing() {
    let h = Harness::new(false);
    let item = |second: u32| {
        format!(
            "<searchMatchItem><logDescriptor><metaId>log.hikvision.com/Exception/illlegealAccess\
             </metaId><StartDateTime>{}10:01:{}Z</StartDateTime><userName>admin</userName>\
             <ipAddress>{}</ipAddress></logDescriptor></searchMatchItem>\n",
            DAY, second, ATTACKER
        )
    };
    let page = |status: &str, items: &[u32]| {
        let body: String = items.iter().map(|s| item(*s)).collect();
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<hik:CMSearchResult \
             xmlns:hik=\"http://www.hikvision.com/ver20/XMLSchema\">{}<hik:matchList>\n{}\
             </hik:matchList></hik:CMSearchResult>",
            status, body
        )
        .into_bytes()
    };
    {
        let mut f = h.fake.lock().unwrap();
        f.raw_pages.push_back(page(
            "<hik:responseStatusStrg version=\"2.0\">MORE</hik:responseStatusStrg>",
            &[10, 11],
        ));
        f.raw_pages.push_back(page("", &[12, 13]));
        f.search_requests = 0;
    }
    util::capture_log();
    let search = h
        .nvr("nvr1")
        .search(
            util::parse_ts(&format!("{}10:00:00", DAY)).unwrap(),
            util::parse_ts(&format!("{}10:05:00", DAY)).unwrap(),
            "",
            None,
        )
        .unwrap();
    // the third page is the fake's own: no entries, which ends the search
    assert_eq!(h.fake.lock().unwrap().search_requests, 3);
    assert_eq!((search.events.len(), search.truncated), (4, false));
    assert_eq!(search.page_size, Some(2));
    assert_eq!(
        logged(
            &util::captured_log(),
            "WARNING nvr1: a result page had no paging status"
        ),
        1
    );
}

/// A last page that takes a search past `MAX_EVENTS` (5000) is cut to it,
/// and the search counts as not complete.
#[test]
fn last_page_is_cut_to_the_entry_cap() {
    let h = Harness::new(false);
    let page = |status: &str| {
        let body =
            "<searchMatchItem><ipAddress>192.0.2.1</ipAddress></searchMatchItem>".repeat(2600);
        format!(
            "<CMSearchResult><responseStatusStrg>{}</responseStatusStrg><matchList>{}\
             </matchList></CMSearchResult>",
            status, body
        )
        .into_bytes()
    };
    {
        let mut f = h.fake.lock().unwrap();
        f.raw_pages.push_back(page("MORE"));
        f.raw_pages.push_back(page("OK"));
    }
    let search = h.nvr("nvr1").search(0, 1, "", None).unwrap();
    assert_eq!((search.events.len(), search.truncated), (5000, true));
}

/// A device clock before 1970 (a reset clock battery) cannot be held by the
/// state file: the NVR is not read until its clock is set, and its state
/// is kept as it was.
#[test]
fn clock_before_1970_is_refused_and_the_state_survives() {
    let mut h = Harness::new(false);
    let before = h.engine.state().cursors["nvr1"].clone();
    // the device shows 1969-12-31T23:00:00 now, 23:00:30 at the next poll
    let skew = -h.host - 3600;
    h.fake.lock().unwrap().skew = skew;
    util::capture_log();
    h.advance(30);
    assert_eq!(
        logged(
            &util::captured_log(),
            "device time \"1969-12-31T23:00:30+02:00\" cannot be used: not a date, or before 1970"
        ),
        1
    );
    assert_eq!(h.engine.state().cursors["nvr1"], before);
    h.restart(); // checks the state file round trip
    assert_eq!(h.engine.state().cursors["nvr1"], before);
    // the clock is set again: the log is read on
    h.fake.lock().unwrap().skew = SKEW;
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert_eq!(h.banned(), vec![ATTACKER]);

    // the same on the very first poll: the NVR stays unknown
    let mut h = Harness::raw(false);
    let skew = -h.host - 3600;
    h.fake.lock().unwrap().skew = skew;
    h.tick();
    assert!(!h.engine.state().cursors.get("nvr1").is_some());
    h.restart();
    assert!(h.engine.state().cursors.is_empty());
}

/// An NVR that ignores the search position and lists oldest first, with
/// more than a page in one second: the cursor moves on by a second per poll
/// instead of staying on that second, and what follows is counted.
#[test]
fn ignored_position_oldest_first_moves_on() {
    let mut h = Harness::with(Opts {
        general: "lookback = 10",
        ..Default::default()
    });
    h.fake.lock().unwrap().stuck_paging = true;
    for _ in 0..70 {
        h.add("10:01:10", "192.168.1.50");
    }
    for second in 30..35 {
        h.add(&format!("10:01:{}", second), ATTACKER);
    }
    h.cycle("10:02:00");
    assert_eq!(h.since("nvr1"), format!("{}10:01:10", DAY));
    for _ in 0..30 {
        h.advance(30);
        if !h.banned().is_empty() {
            break;
        }
    }
    assert_eq!(h.banned(), vec![ATTACKER]);
    assert!(h.since("nvr1") > format!("{}10:01:20", DAY));
}

// ------------------------------------------------------------------ digest

/// C8: the NVR changes its nonce without saying stale=true.
#[test]
fn nonce_rotation_without_stale() {
    let mut h = Harness::new(false);
    {
        let mut f = h.fake.lock().unwrap();
        f.rotate_every = Some(3);
        f.challenges = 0;
        f.isapi_requests = 0;
        f.isapi_ok = 0;
    }
    for _ in 0..6 {
        h.advance(30);
        assert_eq!(h.engine.readers()[0].retry_after(), 0, "no auth backoff");
    }
    h.burst("10:03", ATTACKER, 5);
    h.cycle("10:04:00");
    assert_eq!(h.banned(), vec![ATTACKER]);
    let f = h.fake.lock().unwrap();
    assert!(f.rotations >= 4, "rotations: {}", f.rotations);
    assert!(
        f.challenges <= f.rotations,
        "{} refusals for {} rotations",
        f.challenges,
        f.rotations
    );
    assert_eq!(f.isapi_requests, f.isapi_ok + f.challenges);
}

/// A refused login whose challenge carries a new nonce is retried once,
/// then reported; the NVR sees two attempts at most.
#[test]
fn wrong_password_with_rotating_nonce_backs_off() {
    let mut h = Harness::new(false);
    {
        let mut f = h.fake.lock().unwrap();
        f.nvr_auth_ok = false;
        f.rotate_every = Some(1);
    }
    h.cycle("10:01:00");
    assert!(h.engine.readers()[0].retry_after() > 0);
    assert_eq!(h.fake.lock().unwrap().refused_logins, 2);
}

/// C9: Basic and Digest offered together.
#[test]
fn basic_and_digest_challenges_together() {
    let mut h = Harness::raw(false);
    h.fake.lock().unwrap().basic_first = true;
    h.tick();
    assert_eq!(h.engine.readers()[0].retry_after(), 0);
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert_eq!(h.banned(), vec![ATTACKER]);
}

// ------------------------------------------------- notifications and bans

/// C10: Telegram down with five notifications waiting.
#[test]
fn telegram_down_costs_one_attempt_per_cycle() {
    let mut h = Harness::new(true);
    h.fake.lock().unwrap().tg_fail = true;
    for n in 1..=5 {
        h.burst("10:01", &format!("198.51.100.{}", n), 5);
    }
    h.cycle("10:02:00");
    assert_eq!(h.banned().len(), 5);
    assert_eq!(h.engine.queued_notifications(), 5);
    assert_eq!(h.fake.lock().unwrap().tg_attempts, 1);
    h.advance(30);
    assert_eq!(h.fake.lock().unwrap().tg_attempts, 2);
    h.fake.lock().unwrap().tg_fail = false;
    h.advance(30);
    assert_eq!(h.fake.lock().unwrap().tg_sent.len(), 5);
    assert_eq!(h.engine.queued_notifications(), 0);
}

/// C11a: waiting bans are applied oldest first.
#[test]
fn pending_bans_oldest_first() {
    let mut h = Harness::with(Opts {
        general: "max_bans_per_hour = 1",
        ..Default::default()
    });
    h.burst("10:03", "198.51.100.1", 5);
    h.burst("10:02", "198.51.100.2", 5);
    h.burst("10:01", "198.51.100.3", 5);
    h.cycle("10:04:00");
    assert_eq!(h.banned(), vec!["198.51.100.3"]);
    assert_eq!(h.engine.state().ledger.waiting(), 2);
}

/// A stop signal arrives while the first of three bans is sent: the cycle
/// sends no further ban, no firewall check and no notification, and the
/// state keeps the bans that wait.
#[test]
fn a_stop_ends_the_cycle_after_its_current_step() {
    let mut h = Harness::new(true);
    util::capture_log();
    for n in 1..=3 {
        h.burst("10:01", &format!("198.51.100.{}", n), 5);
    }
    let stop = h.engine.stop_flag();
    h.fake.lock().unwrap().stop_on_put = Some(stop.clone());
    h.cycle("10:05:00"); // the firewall check would be due
    let f = h.fake.lock().unwrap();
    assert_eq!(f.put_log.len(), 1, "{:?}", f.put_log);
    assert_eq!(f.rule_queries.len(), 1, "only the first cycle's check");
    assert_eq!(f.tg_attempts, 0);
    drop(f);
    assert_eq!(h.engine.state().ledger.waiting(), 2);
    assert_eq!(h.engine.state().ledger.sizes().remembered, 1);
    assert_eq!(h.engine.queued_notifications(), 1);
    let log = util::captured_log();
    assert_eq!(
        logged(&log, "stop requested: the rest of this poll is skipped"),
        1
    );
    // no health problem was claimed to be over because of the stop
    assert!(h.engine.alerted_problems().is_empty());
    // a stop before the NVRs are polled: nothing is asked of any device
    let before = h.fake.lock().unwrap().search_requests;
    h.advance(30);
    assert_eq!(h.fake.lock().unwrap().search_requests, before);
    assert_eq!(h.engine.state().ledger.waiting(), 2);
}

/// `Engine::run` saves the state of a cycle that a stop cut short, and does
/// not start another.
#[test]
fn a_stop_during_the_service_saves_the_state() {
    let mut h = Harness::new(false);
    let path = h.dir.join("service-state");
    let now = util::unix_now() as i64;
    // three waiting bans, as a state file holds them
    let mut text = h.engine.state().serialize();
    for n in 1..=3 {
        text.push_str(&format!(
            "pending 198.51.100.{} {} 5 nvr1 admin\n",
            n,
            now - 10 + n
        ));
    }
    h.restart_with(State::parse(&text));
    assert_eq!(h.engine.state().serialize(), text);
    let stop = h.engine.stop_flag();
    h.fake.lock().unwrap().stop_on_put = Some(stop.clone());
    let started = std::time::Instant::now();
    h.engine.run(&path, false);
    assert!(
        started.elapsed().as_secs() < 20,
        "no second cycle, no sleep"
    );
    let saved = State::load(&path).unwrap();
    assert_eq!(&saved, h.engine.state());
    assert_eq!(saved.ledger.waiting(), 2);
    assert_eq!(saved.ledger.sizes().remembered, 1);
    assert_eq!(saved.ledger.sizes().recent_bans, 1);
    assert_eq!(h.fake.lock().unwrap().put_log.len(), 1);
    // stopped before it starts: no cycle at all
    let requests = h.fake.lock().unwrap().isapi_requests;
    h.engine.run(&path, false);
    assert_eq!(h.fake.lock().unwrap().isapi_requests, requests);
}

/// At startup a router that does not answer is asked once (the firewall
/// check), not a second time for the size of the address-list; one that
/// answers is asked both.
#[test]
fn an_unreachable_router_is_asked_once_at_startup() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&connections);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            seen.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    let h = Harness::build(Opts::default());
    let run = |ini: &str| {
        let path = h.dir.join("startup.ini");
        std::fs::write(&path, ini).unwrap();
        std::process::Command::new(env!("CARGO_BIN_EXE_hik-f2b"))
            .arg("--config")
            .arg(&path)
            .arg("--once")
            .output()
            .unwrap()
    };
    let out = run(&h.ini.replace(
        &format!("[mikrotik]\nurl = http://127.0.0.1:{}", h.port),
        &format!("[mikrotik]\nurl = http://127.0.0.1:{}", port),
    ));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", stdout);
    assert_eq!(connections.load(Ordering::SeqCst), 1, "{}", stdout);
    let failed: Vec<&str> = stdout
        .lines()
        .filter(|line| line.contains("firewall check failed"))
        .collect();
    assert_eq!(failed.len(), 1, "{}", stdout);
    // after the time stamp; the end of the reason comes from the network
    // stack
    let text = failed[0].split_once(' ').unwrap().1;
    assert!(
        text.starts_with(&format!(
            "ERROR firewall check failed: cannot reach the firewall: http://127.0.0.1:{}/rest/",
            port
        )) && text.ends_with(" (bans will keep being retried)"),
        "{}",
        text
    );
    assert!(!stdout.contains("address-list cctv_ban has"), "{}", stdout);
    // a router that answers: the check, then the count
    let before = h.fake.lock().unwrap().rest_requests;
    let out = run(&h.ini);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", stdout);
    assert!(
        stdout.contains("MikroTik address-list cctv_ban has 0 entries"),
        "{}",
        stdout
    );
    assert_eq!(h.fake.lock().unwrap().rest_requests - before, 2);
}

/// `MAX_BANNED` holds also where bans are added, not only when the state
/// file is read: the address whose end is nearest is forgotten first.
#[test]
fn remembered_bans_are_bounded() {
    use hik_f2b::ledger::MAX_BANNED;
    let mut h = Harness::new(false);
    let now = h.host as u64;
    let address = |i: usize| std::net::Ipv4Addr::from(0x0B00_0000u32 + i as u32);
    // as many remembered bans as a state file may hold
    let mut text = h.engine.state().serialize();
    for i in 0..MAX_BANNED {
        // address(0) has the nearest end
        let until = if i == 0 { now + 1000 } else { now + 2000 };
        text.push_str(&format!("ban {} {}\n", address(i), until));
    }
    h.restart_with(State::parse(&text));
    assert_eq!(h.engine.state().serialize(), text);
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert_eq!(h.banned(), vec![ATTACKER]);
    assert_eq!(h.engine.state().ledger.sizes().remembered, MAX_BANNED);
    assert!(h.engine.state().ledger.banned_until(attacker()).is_some());
    assert!(h.engine.state().ledger.banned_until(address(0)).is_none());
}

/// The failure times of all addresses together are bounded: with a large
/// `maxretry` more times are kept per address, so fewer addresses are
/// tracked. A state from a run with a smaller `maxretry` is cut down at
/// the start.
#[test]
fn failure_times_are_bounded_in_total() {
    use hik_f2b::ledger::fail_limits;
    use hik_f2b::ledger::MAX_FAIL_TIMES;
    assert_eq!(fail_limits(5), (20, 10_000));
    assert_eq!(fail_limits(100), (400, 500));
    assert_eq!(fail_limits(1000), (4000, 50));
    let mut h = Harness::with(Opts {
        general: "maxretry = 100",
        ..Default::default()
    });
    let address = |i: usize| std::net::Ipv4Addr::from(0x0B00_0000u32 + i as u32);
    let now = h.host;
    // as a state file holds them
    let mut text = h.engine.state().serialize();
    for i in 0..500 {
        text.push_str(&format!("fail {} {}\n", address(i), now - 600 + i as i64));
    }
    h.restart_with(State::parse(&text));
    assert_eq!(h.engine.state().serialize(), text);
    h.add("10:00:40", ATTACKER);
    h.cycle("10:01:00");
    assert_eq!(h.engine.state().ledger.sizes().tracked, 500);
    assert_eq!(h.fails(ATTACKER), 1);
    assert_eq!(
        h.engine.state().ledger.failed_logins(address(0)),
        0,
        "the oldest goes"
    );
    // more than this config allows, from the state file
    let mut text = h.engine.state().serialize();
    for i in 0..700 {
        for _ in 0..450 {
            text.push_str(&format!("fail {} {}\n", address(i), now - 60));
        }
    }
    let state = State::parse(&text);
    for i in 0..700 {
        assert!(state.ledger.failed_logins(address(i)) >= 450);
    }
    h.restart_with(state);
    let sizes = h.engine.state().ledger.sizes();
    assert_eq!(sizes.tracked, 500);
    assert!(sizes.most_fail_times <= 400);
    assert!(sizes.fail_times <= MAX_FAIL_TIMES);
}

/// C11b: the rate limit survives a restart.
#[test]
fn rate_limit_survives_a_restart() {
    let mut h = Harness::with(Opts {
        general: "max_bans_per_hour = 1",
        ..Default::default()
    });
    h.burst("10:01", "198.51.100.1", 5);
    h.burst("10:02", "198.51.100.2", 5);
    h.cycle("10:03:00");
    assert_eq!(h.banned(), vec!["198.51.100.1"]);
    h.restart();
    h.advance(30);
    assert_eq!(
        h.banned(),
        vec!["198.51.100.1"],
        "fresh allowance after restart"
    );
    assert_eq!(h.engine.state().ledger.waiting(), 1);
    // an hour later the next one goes through
    h.cycle("11:03:30");
    assert_eq!(h.banned(), vec!["198.51.100.1", "198.51.100.2"]);
}

/// C11c: an address the router already lists uses no allowance.
#[test]
fn already_listed_uses_no_allowance() {
    let mut h = Harness::with(Opts {
        general: "max_bans_per_hour = 1",
        ..Default::default()
    });
    h.fake.lock().unwrap().bans.push("198.51.100.4".to_string());
    h.burst("10:01", "198.51.100.4", 5);
    h.burst("10:02", "198.51.100.5", 5);
    h.cycle("10:03:00");
    assert_eq!(h.banned(), vec!["198.51.100.4", "198.51.100.5"]);
    assert_eq!(h.engine.state().ledger.waiting(), 0);
}

/// Bans that cannot be applied are not kept for ever.
#[test]
fn pending_ban_expires_after_bantime() {
    let mut h = Harness::new(false);
    h.fake.lock().unwrap().router_down = true;
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert_eq!(h.engine.state().ledger.waiting(), 1);
    h.set_host(h.host + 86400 + 60);
    h.tick();
    assert_eq!(h.engine.state().ledger.waiting(), 0);
}

/// A8: a router that cannot be reached costs one attempt per cycle, not
/// one per waiting address.
#[test]
fn unreachable_router_is_tried_once_per_cycle() {
    // accepts connections and drops them without an answer
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&connections);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            seen.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    let mut h = Harness::new(false);
    h.ini = h.ini.replace(
        &format!("[mikrotik]\nurl = http://127.0.0.1:{}", h.port),
        &format!("[mikrotik]\nurl = http://127.0.0.1:{}", port),
    );
    h.restart();
    for n in 1..=3 {
        h.burst("10:01", &format!("198.51.100.{}", n), 5);
    }
    h.cycle("10:02:00");
    assert_eq!(h.engine.state().ledger.waiting(), 3);
    assert_eq!(h.engine.state().ledger.sizes().recent_bans, 0);
    assert_eq!(connections.load(Ordering::SeqCst), 1);
    h.advance(30);
    assert_eq!(connections.load(Ordering::SeqCst), 2);
}

/// A6: more entries in one second than one poll can read: the cursor still
/// moves on, whichever order the NVR lists them in.
#[test]
fn capped_poll_still_makes_progress() {
    for newest_first in [false, true] {
        let mut h = Harness::new(false);
        let fake = Arc::clone(&h.fake);
        let before = {
            // an address in ignoreip, so that nothing is banned
            let mut f = fake.lock().unwrap();
            f.newest_first = newest_first;
            for n in 0..3300 {
                f.entries.push(Entry {
                    ts: format!("{}10:01:10", DAY),
                    minor: "illlegealAccess".to_string(),
                    ip: "192.168.1.50".to_string(),
                    user: format!("u{:04}", n).into_bytes(),
                });
            }
            f.entries.sort();
            f.search_requests
        };
        let warning = "more log entries within one second than can be read in one poll; \
                       moving on by one second";
        util::capture_log();
        h.cycle("10:02:00");
        // 50 pages of that second, then one search of the time before it
        assert_eq!(h.fake.lock().unwrap().search_requests - before, 51);
        assert_eq!(h.since("nvr1"), format!("{}10:01:10", DAY));
        assert_eq!(logged(&util::captured_log(), warning), 0);
        h.cycle("10:02:30");
        assert_eq!(h.since("nvr1"), format!("{}10:01:11", DAY));
        assert_eq!(logged(&util::captured_log(), warning), 1);
        h.cycle("10:03:00");
        assert_eq!(h.since("nvr1"), format!("{}10:01:12", DAY));
        assert!(h.engine.state().cursors["nvr1"].seen() >= 3200);
    }
}

/// `count` failed logins from each address, `per_second` a second from
/// `DAY` 10:01:00 on (device time), the addresses taken in turn.
fn backlog(fake: &Mutex<Fake>, addresses: &[String], count: usize, per_second: usize) {
    let start = util::parse_ts(&format!("{}10:01:00", DAY)).unwrap();
    let mut f = fake.lock().unwrap();
    for n in 0..addresses.len() * count {
        f.entries.push(Entry {
            ts: device(start + (n / per_second) as i64),
            minor: "illlegealAccess".to_string(),
            ip: addresses[n % addresses.len()].clone(),
            user: b"admin".to_vec(),
        });
    }
    f.entries.sort();
}

/// 600 addresses with 12 failed logins each and three with 20 each (for
/// maxretry = 20): 7260 entries from 10:01:00 to 10:40:59, more than two
/// searches return (50 pages of 64 entries each).
fn big_backlog(h: &Harness) -> (Vec<String>, Vec<String>) {
    let light: Vec<String> = (0..600)
        .map(|n| match n / 256 {
            0 => format!("192.0.2.{}", n),
            1 => format!("198.51.100.{}", n - 256),
            _ => format!("203.0.113.{}", n - 512),
        })
        .collect();
    backlog(&h.fake, &light, 12, 3);
    let heavy: Vec<String> = (200..203).map(|n| format!("203.0.113.{}", n)).collect();
    for minute in 0..20 {
        for address in &heavy {
            h.add(&format!("10:{:02}:30", 1 + 2 * minute), address);
        }
    }
    (light, heavy)
}

/// An NVR that lists newest first: a backlog larger than one search is read
/// to its end in the same poll, and every failed login is counted once.
#[test]
fn newest_first_backlog_is_counted_once() {
    let mut h = Harness::with(Opts {
        general: "maxretry = 20",
        ..Default::default()
    });
    h.fake.lock().unwrap().newest_first = true;
    let (light, heavy) = big_backlog(&h);
    util::capture_log();
    let before = h.fake.lock().unwrap().search_requests;
    h.cycle("10:42:00");
    let pages = h.fake.lock().unwrap().search_requests - before;
    assert!(pages > 100, "{} pages: more than two searches", pages);
    let log = util::captured_log();
    assert_eq!(logged(&log, "SKIPPING"), 0);
    assert_eq!(logged(&log, "within one second"), 0);
    for _ in 0..3 {
        for address in &light {
            assert_eq!(h.fails(address), 12, "{}", address);
        }
        let mut banned = h.banned();
        banned.sort();
        assert_eq!(banned, heavy);
        assert_eq!(h.since("nvr1"), format!("{}10:40:59", DAY));
        // the next polls read the overlap again and count nothing twice
        h.advance(30);
    }
}

/// The same backlog listed oldest first is read as before: one part per
/// poll, with the cursor at the newest entry read.
#[test]
fn oldest_first_backlog_is_read_over_several_polls() {
    let mut h = Harness::with(Opts {
        general: "maxretry = 20",
        ..Default::default()
    });
    let (light, heavy) = big_backlog(&h);
    h.cycle("10:42:00");
    let cursor = h.since("nvr1");
    assert!(cursor < format!("{}10:40:00", DAY), "{}", cursor);
    run(&mut h, 4, 30);
    assert_eq!(h.since("nvr1"), format!("{}10:40:59", DAY));
    for address in &light {
        assert_eq!(h.fails(address), 12, "{}", address);
    }
    let mut banned = h.banned();
    banned.sort();
    assert_eq!(banned, heavy);
}

/// Newest first, and the window holds more than `MAX_SEARCHES` (4)
/// searches return: the newest part is counted, and the oldest part is
/// reported in an ERROR line with its time range.
#[test]
fn newest_first_backlog_beyond_the_bound_is_reported() {
    let mut h = Harness::new(false);
    h.fake.lock().unwrap().newest_first = true;
    // 13,500 entries (ignoreip) from 10:01:00 to 10:38:29, six a second
    backlog(&h.fake, &["192.168.1.50".to_string()], 13_500, 6);
    // in the oldest part, which cannot be read in one poll
    h.burst("10:01", ATTACKER, 5);
    // newer than the rest
    h.burst("10:39", "198.51.100.8", 5);
    util::capture_log();
    h.cycle("10:40:00");
    let log = util::captured_log();
    let skipped: Vec<&String> = log.iter().filter(|l| l.contains("SKIPPING")).collect();
    assert_eq!(skipped.len(), 1, "{:?}", skipped);
    assert!(
        skipped[0].starts_with(&format!(
            "ERROR nvr1: not every log entry in {}09:58:00Z .. {}10:0",
            DAY, DAY
        )),
        "{}",
        skipped[0]
    );
    assert!(
        skipped[0].contains("(device time) could be read with 4 searches in one poll"),
        "{}",
        skipped[0]
    );
    assert_eq!(h.banned(), vec!["198.51.100.8"]);
    assert_eq!(h.fails(ATTACKER), 0);
    assert_eq!(h.since("nvr1"), format!("{}10:39:14", DAY));
}

/// C12: no router at all, only Telegram.
#[test]
fn notify_only_mode() {
    let mut h = Harness::with(Opts {
        telegram: true,
        mikrotik: false,
        ..Default::default()
    });
    assert!(h.config().mikrotik.is_none());
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    let sent = h.fake.lock().unwrap().tg_sent.clone();
    assert_eq!(sent.len(), 1);
    let text = text_of(&sent[0]);
    assert!(
        text.starts_with("\u{26d4} hik-f2b: 198.51.100.7 detected, no firewall configured\n"),
        "{}",
        text
    );
    assert!(h.engine.state().ledger.banned_until(attacker()).is_some());
    // the same address is not reported again on its next burst
    h.burst("10:20", ATTACKER, 5);
    h.cycle("10:21:00");
    assert_eq!(h.fake.lock().unwrap().tg_sent.len(), 1);
    assert_eq!(h.fails(ATTACKER), 0);
    assert_eq!(h.fake.lock().unwrap().router_requests, 0);
    // ... until bantime has passed
    h.set_host(host_of("10:02:00") + 86400 + 60);
    let fake = Arc::clone(&h.fake);
    for s in 0..5 {
        Harness::add_at(&fake, &device(h.host + SKEW + s), ATTACKER);
    }
    h.advance(30);
    assert_eq!(h.fake.lock().unwrap().tg_sent.len(), 2);
    assert_eq!(h.fake.lock().unwrap().router_requests, 0);
}

/// Neither a router nor Telegram: detections only go to the log.
#[test]
fn log_only_mode() {
    let mut h = Harness::with(Opts {
        mikrotik: false,
        ..Default::default()
    });
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert!(h.engine.state().ledger.banned_until(attacker()).is_some());
    assert_eq!(h.engine.queued_notifications(), 0);
    assert_eq!(h.fake.lock().unwrap().router_requests, 0);
}

/// C13: a restart neither double-counts nor misses entries.
#[test]
fn restart_neither_double_counts_nor_misses() {
    let mut h = Harness::new(false);
    h.add("10:01:10", ATTACKER);
    h.add("10:01:20", ATTACKER);
    h.cycle("10:02:00");
    assert_eq!(h.fails(ATTACKER), 2);
    h.restart();
    h.add("10:02:10", ATTACKER);
    h.cycle("10:02:30");
    assert_eq!(h.fails(ATTACKER), 3);
    h.restart();
    h.add("10:02:40", ATTACKER);
    h.cycle("10:03:00");
    assert_eq!(h.fails(ATTACKER), 4);
    h.add("10:03:10", ATTACKER);
    h.cycle("10:03:30");
    assert_eq!(h.banned(), vec![ATTACKER]);
}

// --------------------------------------------------------------- ban time

/// Adds the given template to the `[telegram]` section (the last one) and
/// restarts the engine with it.
fn with_message(h: &mut Harness, message: &str) {
    assert!(h.ini.trim_end().ends_with("message_thread_id = 42"));
    h.ini.push_str(&format!("message = {}\n", message));
    h.restart();
}

fn telegram_texts(h: &Harness) -> Vec<String> {
    let sent = h.fake.lock().unwrap().tg_sent.clone();
    sent.iter().map(String::as_str).map(text_of).collect()
}

/// A permanent ban is a static address-list entry: no timeout member.
#[test]
fn permanent_ban_has_no_timeout() {
    let mut h = Harness::with(Opts {
        telegram: true,
        general: "bantime = permanent",
        ..Default::default()
    });
    with_message(&mut h, "{ip} {action}|{bantime}");
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert_eq!(h.banned(), vec![ATTACKER]);
    let body = h.fake.lock().unwrap().ban_bodies[0].clone();
    assert_eq!(
        body,
        "{\"list\":\"cctv_ban\",\"address\":\"198.51.100.7\",\
         \"comment\":\"hik-f2b nvr1 user=admin 2026-01-10T08:01:14Z\"}"
    );
    assert!(!body.contains("timeout"), "{}", body);
    assert_eq!(
        telegram_texts(&h),
        vec!["198.51.100.7 banned permanently|permanent"]
    );
    // the engine itself remembers the ban for 24 hours
    let until = h.engine.state().ledger.banned_until(attacker()).unwrap();
    assert_eq!(until, host_of("10:02:00") as u64 + 86400);
}

/// The same scenario with a timed ban still sends the timeout, written as
/// before whatever unit the config used.
#[test]
fn timed_ban_with_a_suffix_keeps_the_timeout() {
    let mut h = Harness::with(Opts {
        telegram: true,
        general: "bantime = 12h\nfindtime = 1h",
        ..Default::default()
    });
    with_message(&mut h, "{ip} {action}|{bantime}");
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    let body = h.fake.lock().unwrap().ban_bodies[0].clone();
    assert_eq!(
        body,
        "{\"list\":\"cctv_ban\",\"address\":\"198.51.100.7\",\"timeout\":\"12:00:00\",\
         \"comment\":\"hik-f2b nvr1 user=admin 2026-01-10T08:01:14Z\"}"
    );
    assert_eq!(
        telegram_texts(&h),
        vec!["198.51.100.7 banned for 12:00:00|12:00:00"]
    );
    assert_eq!(h.config().findtime, 3600);
}

#[test]
fn permanent_dry_run_wording() {
    let mut h = Harness::with(Opts {
        telegram: true,
        general: "bantime = permanent\ndry_run = true",
        ..Default::default()
    });
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert!(h.banned().is_empty());
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 1);
    assert!(
        texts[0]
            .starts_with("\u{26d4} hik-f2b: 198.51.100.7 would be banned permanently (dry run)\n"),
        "{}",
        texts[0]
    );
}

/// Without a router, a permanent bantime reports an address once per 24
/// hours.
#[test]
fn permanent_notify_only_reports_once_a_day() {
    let mut h = Harness::with(Opts {
        telegram: true,
        mikrotik: false,
        general: "bantime = permanent",
        ..Default::default()
    });
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 1);
    assert!(
        texts[0].starts_with("\u{26d4} hik-f2b: 198.51.100.7 detected, no firewall configured\n"),
        "{}",
        texts[0]
    );
    let fake = Arc::clone(&h.fake);
    let burst_at = |h: &mut Harness, host: i64| {
        h.set_host(host);
        for s in 0..5 {
            Harness::add_at(&fake, &device(host + SKEW + s), ATTACKER);
        }
        h.advance(30);
    };
    // not again within 24 hours ...
    burst_at(&mut h, host_of("10:02:00") + 23 * 3600);
    assert_eq!(telegram_texts(&h).len(), 1);
    assert_eq!(h.fails(ATTACKER), 0);
    // ... but after them
    burst_at(&mut h, host_of("10:02:00") + 86400 + 60);
    assert_eq!(telegram_texts(&h).len(), 2);
    assert_eq!(h.fake.lock().unwrap().router_requests, 0);
}

/// A permanent ban that cannot be applied waits 24 hours, not for ever.
#[test]
fn permanent_pending_ban_expires_after_a_day() {
    let mut h = Harness::with(Opts {
        general: "bantime = permanent",
        ..Default::default()
    });
    h.fake.lock().unwrap().router_down = true;
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert_eq!(h.engine.state().ledger.waiting(), 1);
    h.set_host(h.host + 23 * 3600);
    h.tick();
    assert_eq!(h.engine.state().ledger.waiting(), 1);
    h.set_host(h.host + 3600 + 60);
    h.tick();
    assert_eq!(h.engine.state().ledger.waiting(), 0);
    assert!(h.banned().is_empty());
}

// ---------------------------------------------------------- health alerts

const WARN: &str = "\u{26a0}\u{fe0f} hik-f2b: ";
const OK: &str = "\u{2705} hik-f2b: ";

#[test]
fn nvr_outage_is_alerted_once_then_recovery() {
    let mut h = Harness::new(true);
    h.fake.lock().unwrap().nvr_down = true;
    util::capture_log();
    run(&mut h, 20, 30); // first failure at 10:00:30, now 10:10:00
    assert!(telegram_texts(&h).is_empty(), "alerted before alert_after");
    // each failed poll: the hik-f2b log names the URL, the end of the
    // reason comes from the network stack
    let log = util::captured_log();
    let poll_failed = format!(
        "WARNING nvr1: poll failed: http://127.0.0.1:{}/ISAPI/System/time: ",
        h.port
    );
    assert_eq!(starting(&log, &poll_failed), 20, "{:?}", log);
    h.advance(30);
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 1, "{:?}", texts);
    assert!(
        texts[0].starts_with(&format!("{}nvr1 cannot be read for 10 min: ", WARN)),
        "{}",
        texts[0]
    );
    // the reason names neither the address nor the URL of the NVR
    assert!(!texts[0].contains("127.0.0.1"), "{}", texts[0]);
    assert!(!texts[0].contains("http"), "{}", texts[0]);
    let log = util::captured_log();
    assert_eq!(
        starting(
            &log,
            "ERROR health alert [nvr:nvr1]: hik-f2b: nvr1 cannot be read for 10 min: <url>: "
        ),
        1,
        "{:?}",
        log
    );
    run(&mut h, 20, 30);
    assert_eq!(telegram_texts(&h).len(), 1, "alerted more than once");
    assert_eq!(h.engine.alerted_problems(), vec!["nvr:nvr1"]);

    h.fake.lock().unwrap().nvr_down = false;
    util::capture_log();
    h.advance(30); // 10:21:00
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 2, "{:?}", texts);
    assert_eq!(
        texts[1],
        format!("{}nvr1 is readable again (after 20 min)", OK)
    );
    let log = util::captured_log();
    assert_eq!(
        exactly(
            &log,
            "INFO health recovered [nvr:nvr1]: hik-f2b: nvr1 is readable again (after 20 min)"
        ),
        1,
        "{:?}",
        log
    );
    assert!(h.engine.alerted_problems().is_empty());
    run(&mut h, 4, 30);
    assert_eq!(telegram_texts(&h).len(), 2);
}

#[test]
fn short_nvr_outage_is_not_news() {
    let mut h = Harness::new(true);
    h.fake.lock().unwrap().nvr_down = true;
    run(&mut h, 19, 30);
    h.fake.lock().unwrap().nvr_down = false;
    run(&mut h, 40, 30);
    assert!(telegram_texts(&h).is_empty());
}

/// An NVR in auth backoff is not polled, but its problem is still alerted
/// on time.
#[test]
fn rejected_login_is_alerted_during_the_backoff() {
    let mut h = Harness::new(true);
    h.fake.lock().unwrap().nvr_auth_ok = false;
    h.advance(30); // 10:00:30: rejected, next try at 10:15:30
    run(&mut h, 19, 30);
    assert!(telegram_texts(&h).is_empty());
    h.advance(30); // 10:10:30
    assert_eq!(
        telegram_texts(&h),
        vec![format!(
            "{}nvr1 cannot be read for 10 min: login rejected (HTTP 401)",
            WARN
        )]
    );
    assert_eq!(h.fake.lock().unwrap().refused_logins, 1, "no extra login");
}

#[test]
fn router_outage_is_alerted_and_bans_still_reported() {
    let mut h = Harness::new(true);
    h.fake.lock().unwrap().router_unreachable = true;
    h.burst("10:01", ATTACKER, 5);
    util::capture_log();
    h.cycle("10:02:00"); // the ban fails: the outage starts now
    assert_eq!(h.engine.state().ledger.waiting(), 1);
    // the end of the reason comes from the network stack
    let log = util::captured_log();
    assert_eq!(
        starting(
            &log,
            &format!(
                "ERROR cannot ban 198.51.100.7 on MikroTik address-list cctv_ban, will retry \
                 next cycle: cannot reach the firewall: \
                 http://127.0.0.1:{}/rest/ip/firewall/address-list: ",
                h.port
            )
        ),
        1,
        "{:?}",
        log
    );
    run(&mut h, 19, 30);
    assert!(telegram_texts(&h).is_empty());
    h.advance(30); // 10:12:00
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 1, "{:?}", texts);
    assert!(
        texts[0].starts_with(&format!(
            "{}the firewall is not usable for 10 min: cannot reach the firewall: ",
            WARN
        )),
        "{}",
        texts[0]
    );
    assert!(!texts[0].contains("127.0.0.1"), "{}", texts[0]);
    assert!(h.banned().is_empty());

    // back: the waiting ban is applied and announced as before, then the
    // recovery
    h.fake.lock().unwrap().router_unreachable = false;
    h.advance(30); // 10:12:30
    assert_eq!(h.banned(), vec![ATTACKER]);
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 3, "{:?}", texts);
    assert!(
        texts[1].starts_with("\u{26d4} hik-f2b: 198.51.100.7 banned for 1d00:00:00\n"),
        "{}",
        texts[1]
    );
    assert_eq!(
        texts[2],
        format!("{}the firewall is usable again (after 10 min)", OK)
    );

    // an outage with no ban waiting is found by the periodic check
    // (10:17:30, 10:22:30, 10:27:30)
    h.fake.lock().unwrap().router_unreachable = true;
    util::capture_log();
    run(&mut h, 40, 30);
    let log = util::captured_log();
    assert_eq!(
        starting(
            &log,
            &format!(
                "WARNING firewall check failed: cannot reach the firewall: \
                 http://127.0.0.1:{}/rest/ip/firewall/",
                h.port
            )
        ),
        4,
        "{:?}",
        log
    );
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 4, "{:?}", texts);
    assert!(
        texts[3].starts_with(&format!("{}the firewall is not usable for 10 min: ", WARN)),
        "{}",
        texts[3]
    );
}

#[test]
fn missing_drop_rule_is_alerted_until_a_rule_is_back() {
    let mut h = Harness::new(true); // checked at 10:00:00: the rule is there
    {
        let mut f = h.fake.lock().unwrap();
        assert_eq!(f.rule_queries.len(), 1, "raw has the rule: one request");
        f.rules.clear(); // a configuration rollback
        f.rule_queries.clear();
    }
    run(&mut h, 29, 30); // checks at 10:05 and 10:10
    assert!(telegram_texts(&h).is_empty());
    h.advance(30); // 10:15:00
    assert_eq!(
        telegram_texts(&h),
        vec![format!(
            "{}banned addresses are not blocked for 10 min: no enabled rule in \
             /ip/firewall/raw or /ip/firewall/filter has src-address-list=cctv_ban",
            WARN
        )]
    );
    let queries = h.fake.lock().unwrap().rule_queries.clone();
    assert_eq!(queries.len(), 6, "two requests per check: {:?}", queries);
    // `,` is percent-encoded by the HTTP client
    assert_eq!(
        queries[0],
        "/rest/ip/firewall/raw?src-address-list=cctv_ban&.proplist=.id%2Cdisabled%2Cinvalid"
    );
    assert_eq!(
        queries[1],
        "/rest/ip/firewall/filter?src-address-list=cctv_ban&.proplist=.id%2Cdisabled%2Cinvalid"
    );

    // a disabled rule does not count
    h.fake
        .lock()
        .unwrap()
        .rules
        .push(Rule::new("filter", "cctv_ban", true));
    h.advance(300); // 10:20
    assert_eq!(telegram_texts(&h).len(), 1);
    // an enabled one in filter does
    h.fake
        .lock()
        .unwrap()
        .rules
        .push(Rule::new("filter", "cctv_ban", false));
    h.advance(300); // 10:25
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 2, "{:?}", texts);
    assert_eq!(
        texts[1],
        format!("{}banned addresses are blocked again (after 20 min)", OK)
    );
}

/// The rule check against replies shaped like RouterOS 7.18.1's: some
/// enabled rules have no `disabled` member, others `"disabled":"false"`.
#[test]
fn rule_check_reads_the_disabled_member_as_the_router_prints_it() {
    use hik_f2b::action::HealthError;
    let h = Harness::new(false);
    let set = |rules: &[(&'static str, bool)]| {
        h.fake.lock().unwrap().rules = rules
            .iter()
            .map(|(t, d)| Rule::new(t, "cctv_ban", *d))
            .collect();
    };
    let router = h.router();
    let check = || router.check().map(|c| c.found);

    // an enabled raw rule (no `disabled` member) is found with one request
    set(&[("raw", false)]);
    h.fake.lock().unwrap().rule_queries.clear();
    assert_eq!(
        check(),
        Ok("1 enabled rule(s) in /ip/firewall/raw with src-address-list=cctv_ban".to_string())
    );
    assert_eq!(h.fake.lock().unwrap().rule_queries.len(), 1);

    // a disabled raw rule ("disabled":"true") is not; filter is asked next
    set(&[("raw", true), ("filter", false), ("filter", true)]);
    assert_eq!(
        check(),
        Ok(
            "1 enabled rule(s) in /ip/firewall/filter with src-address-list=cctv_ban; left out: \
             2 disabled"
                .to_string()
        )
    );

    // only disabled rules, in both tables
    set(&[("raw", true), ("filter", true)]);
    assert!(matches!(check(), Err(HealthError::NotEnforced(_))));
    // a rule for another list does not count
    h.fake.lock().unwrap().rules = vec![Rule::new("raw", "other", false)];
    assert!(matches!(check(), Err(HealthError::NotEnforced(_))));
    // the enabled rule with and without `"disabled":"false"`
    set(&[("raw", true), ("raw", false)]);
    assert!(check().is_ok());
    set(&[("raw", false), ("raw", true)]);
    assert!(check().is_ok());
}

/// A rule RouterOS marks invalid (its interface list was removed, say)
/// blocks nothing: it is left out, and the check says so.
#[test]
fn invalid_rules_do_not_count() {
    use hik_f2b::action::HealthError;
    let mut h = Harness::new(true);
    let check = |h: &Harness| h.router().check().map(|c| c.found);
    h.fake.lock().unwrap().rules = vec![Rule::invalid("raw", "cctv_ban")];
    assert_eq!(
        check(&h),
        Err(HealthError::NotEnforced(
            "no enabled rule in /ip/firewall/raw or /ip/firewall/filter has \
             src-address-list=cctv_ban; left out: 1 invalid"
                .to_string()
        ))
    );
    // an invalid rule in raw, a good one in filter
    h.fake.lock().unwrap().rules = vec![
        Rule::invalid("raw", "cctv_ban"),
        Rule::new("raw", "cctv_ban", true),
        Rule::new("filter", "cctv_ban", false),
    ];
    assert_eq!(
        check(&h),
        Ok(
            "1 enabled rule(s) in /ip/firewall/filter with src-address-list=cctv_ban; left \
            out: 1 disabled, 1 invalid"
                .to_string()
        )
    );
    // a dynamic rule reports neither property, and counts
    h.fake.lock().unwrap().rules = vec![Rule::dynamic("raw", "cctv_ban")];
    assert_eq!(
        check(&h),
        Ok("1 enabled rule(s) in /ip/firewall/raw with src-address-list=cctv_ban".to_string())
    );
    // the alert names the reason
    h.fake.lock().unwrap().rules = vec![Rule::invalid("raw", "cctv_ban")];
    run(&mut h, 3, 300);
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 1, "{:?}", texts);
    assert!(texts[0].ends_with("left out: 1 invalid"), "{}", texts[0]);
}

/// An answer that is not the JSON asked for (a proxy's login page, say)
/// is an error, never "no rule" or "the router answers".
#[test]
fn an_answer_that_is_not_json_is_an_error() {
    use hik_f2b::action::{BanError, BanTime, HealthError};
    for check_rule in [true, false] {
        let h = Harness::with(Opts {
            mikrotik_extra: if check_rule { "" } else { "check_rule = false" },
            ..Default::default()
        });
        h.fake.lock().unwrap().rest_html = true;
        let fw = h.router();
        match fw.check().map(|c| c.found) {
            Err(HealthError::Unusable(e)) => {
                assert!(
                    e.starts_with("the firewall answers with an error: "),
                    "{}",
                    e
                );
                assert!(e.contains("<html>"), "{}", e);
            }
            other => panic!("{:?}", other),
        }
        match fw.ban(attacker(), BanTime::Seconds(60), "t") {
            Err(BanError::Router(e)) => assert!(
                e.starts_with("the answer to the ban is not the JSON object RouterOS sends"),
                "{}",
                e
            ),
            other => panic!("{:?}", other),
        }
    }
}

/// Error answers that say nothing about one address stop the queue for
/// the cycle and raise one alert, under `firewall`; only an answer about
/// the address (HTTP 400) is a refused ban.
#[test]
fn router_errors_are_classified_and_bound_the_requests() {
    // (status, for PUT only, the start of the alert reason)
    for (status, put_only, reason) in [
        (401, false, "the firewall refuses our login: HTTP 401: "),
        (403, false, "the firewall refuses our login: HTTP 403: "),
        (500, true, "the firewall answers with an error: HTTP 500: "),
        (503, false, "the firewall answers with an error: HTTP 503: "),
    ] {
        let mut h = Harness::new(true);
        {
            let mut f = h.fake.lock().unwrap();
            if put_only {
                f.put_status = Some(status);
            } else {
                f.rest_status = Some(status);
            }
        }
        for n in 1..=5 {
            h.burst("10:01", &format!("198.51.100.{}", n), 5);
        }
        let before = h.fake.lock().unwrap().rest_requests;
        h.cycle("10:02:00");
        // one ban request and no lookup, whatever the number waiting; no
        // periodic check either (it is not due yet)
        let f = h.fake.lock().unwrap();
        assert_eq!(f.rest_requests - before, 1, "HTTP {}", status);
        assert!(f.lookups.is_empty(), "HTTP {}", status);
        drop(f);
        assert_eq!(h.engine.state().ledger.waiting(), 5);
        // a cycle with the periodic check: at most one more request per table
        let before = h.fake.lock().unwrap().rest_requests;
        h.cycle("10:05:00");
        let used = h.fake.lock().unwrap().rest_requests - before;
        assert!(used <= 3, "HTTP {}: {} requests", status, used);
        run(&mut h, 15, 30); // 10:12:30
        let texts = telegram_texts(&h);
        assert_eq!(texts.len(), 1, "HTTP {}: one alert: {:?}", status, texts);
        assert!(
            texts[0].starts_with(&format!(
                "{}the firewall is not usable for 10 min: {}",
                WARN, reason
            )),
            "{}",
            texts[0]
        );
        assert_eq!(
            h.engine.alerted_problems(),
            vec!["firewall"],
            "HTTP {}",
            status
        );
        // fixed: the bans go through, one recovery
        {
            let mut f = h.fake.lock().unwrap();
            f.rest_status = None;
            f.put_status = None;
        }
        h.advance(30);
        assert_eq!(h.banned().len(), 5, "HTTP {}", status);
        let texts = telegram_texts(&h);
        assert_eq!(texts.len(), 7, "HTTP {}: {:?}", status, texts);
        assert!(texts[6].starts_with(&format!("{}the firewall is usable again", OK)));
        assert!(h.engine.alerted_problems().is_empty());
    }
}

/// HTTP 400 is about this request: the address is looked up, and an
/// unlisted one is refused, per address; at most two requests per address.
#[test]
fn a_refused_ban_costs_two_requests_per_address() {
    let mut h = Harness::new(false);
    h.fake.lock().unwrap().refuse_writes = true;
    for n in 1..=3 {
        h.burst("10:01", &format!("198.51.100.{}", n), 5);
    }
    let before = h.fake.lock().unwrap().rest_requests;
    h.cycle("10:02:00");
    let f = h.fake.lock().unwrap();
    assert_eq!(f.rest_requests - before, 6);
    assert_eq!(f.lookups.len(), 3);
    drop(f);
    assert_eq!(h.engine.state().ledger.waiting(), 3);
    assert_eq!(h.engine.alerted_problems(), Vec::<String>::new());
}

#[test]
fn missing_drop_rule_is_reminded_daily() {
    let mut h = Harness::new(true);
    h.fake.lock().unwrap().rules.clear();
    util::capture_log();
    run(&mut h, 3, 300); // checks at 10:05, 10:10, 10:15: alert
    assert_eq!(telegram_texts(&h).len(), 1);
    let rule = "no enabled rule in /ip/firewall/raw or /ip/firewall/filter has \
                src-address-list=cctv_ban";
    let log = util::captured_log();
    assert_eq!(
        exactly(&log, &format!("WARNING firewall check failed: {}", rule)),
        3,
        "{:?}",
        log
    );
    assert_eq!(
        exactly(
            &log,
            &format!(
                "ERROR health alert [firewall-rule]: hik-f2b: banned addresses are not \
                 blocked for 10 min: {}",
                rule
            )
        ),
        1,
        "{:?}",
        log
    );
    run(&mut h, 23, 3600);
    h.advance(3300); // one day after the alert, less 5 minutes
    assert_eq!(telegram_texts(&h).len(), 1);
    util::capture_log();
    h.advance(300);
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 2, "{:?}", texts);
    assert!(
        texts[1].starts_with(&format!(
            "{}banned addresses are not blocked for 24 h: ",
            WARN
        )),
        "{}",
        texts[1]
    );
    let log = util::captured_log();
    assert_eq!(
        exactly(
            &log,
            &format!(
                "ERROR health reminder [firewall-rule]: hik-f2b: banned addresses are not \
                 blocked for 24 h: {}",
                rule
            )
        ),
        1,
        "{:?}",
        log
    );
}

#[test]
fn rule_check_switched_off_sends_no_rule_request() {
    let mut h = Harness::with(Opts {
        telegram: true,
        mikrotik_extra: "check_rule = false",
        ..Default::default()
    });
    h.fake.lock().unwrap().rules.clear();
    run(&mut h, 6, 300);
    let f = h.fake.lock().unwrap();
    assert!(f.rule_queries.is_empty(), "{:?}", f.rule_queries);
    // the router is still checked for being reachable
    assert_eq!(f.identity_requests, 7);
    assert!(f.tg_sent.is_empty());
}

#[test]
fn health_alerts_switched_off_send_nothing_but_bans() {
    let mut h = Harness::with(Opts {
        telegram: true,
        telegram_extra: "health_alerts = false",
        ..Default::default()
    });
    h.fake.lock().unwrap().rules.clear();
    h.burst("10:01", ATTACKER, 5);
    run(&mut h, 40, 30);
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 1, "{:?}", texts);
    assert!(
        texts[0].starts_with("\u{26d4} hik-f2b: 198.51.100.7 banned"),
        "{}",
        texts[0]
    );
    // the problem is tracked (and logged) all the same
    assert_eq!(h.engine.alerted_problems(), vec!["firewall-rule"]);
}

#[test]
fn held_back_bans_are_alerted() {
    let mut h = Harness::with(Opts {
        telegram: true,
        general: "max_bans_per_hour = 1",
        ..Default::default()
    });
    h.burst("10:01", "198.51.100.1", 5);
    h.burst("10:01", "198.51.100.2", 5);
    h.cycle("10:02:00");
    run(&mut h, 20, 30); // 10:12:00
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 2, "{:?}", texts);
    assert_eq!(
        texts[1],
        format!(
            "{}new bans are held back by max_bans_per_hour for 10 min: \
             1 address(es) waiting, limit 1 per hour",
            WARN
        )
    );
    h.cycle("11:02:30"); // the allowance is back
    assert_eq!(h.banned().len(), 2);
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 4, "{:?}", texts);
    assert!(texts[2].contains("198.51.100.2 banned"), "{}", texts[2]);
    assert_eq!(
        texts[3],
        format!("{}bans are no longer held back (after 60 min)", OK)
    );
}

/// A router that answers reads but refuses every ban: the read checks pass,
/// the refused bans raise their own alert, and only an accepted ban ends it.
#[test]
fn refused_bans_are_alerted_until_a_ban_is_accepted() {
    let mut h = Harness::with(Opts {
        telegram: true,
        general: "bantime = 7d",
        ..Default::default()
    });
    h.fake.lock().unwrap().refuse_writes = true;
    h.burst("10:01", ATTACKER, 5);
    util::capture_log();
    h.cycle("10:02:00"); // refused: the problem starts now
    assert_eq!(h.engine.state().ledger.waiting(), 1);
    let log = util::captured_log();
    assert_eq!(
        exactly(
            &log,
            "ERROR cannot ban 198.51.100.7 on MikroTik address-list cctv_ban, will retry: \
             HTTP 400: {\"detail\":\"not enough permissions (9)\",\"error\":400,\
             \"message\":\"Bad Request\"}"
        ),
        1,
        "{:?}",
        log
    );
    run(&mut h, 19, 30); // read checks at 10:05 and 10:10 pass
    assert!(telegram_texts(&h).is_empty());
    h.advance(30); // 10:12:00
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 1, "{:?}", texts);
    assert!(
        texts[0].starts_with(&format!(
            "{}the firewall refuses bans for 10 min: 198.51.100.7: HTTP 400: ",
            WARN
        )),
        "{}",
        texts[0]
    );
    assert!(texts[0].contains("not enough permissions"), "{}", texts[0]);
    assert!(!texts[0].contains("127.0.0.1"), "{}", texts[0]);
    // the router still answers every read
    assert!(h.router().check().is_ok());

    // a day of read checks does not clear it; the reminder comes after 24 h
    run(&mut h, 23, 3600);
    h.advance(3300); // one day after the alert, less 5 minutes
    assert_eq!(telegram_texts(&h).len(), 1);
    assert_eq!(h.engine.alerted_problems(), vec!["ban-refused"]);
    h.advance(300);
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 2, "{:?}", texts);
    assert!(
        texts[1].starts_with(&format!("{}the firewall refuses bans for 24 h: ", WARN)),
        "{}",
        texts[1]
    );
    assert!(h.banned().is_empty());

    // writes are allowed again: the waiting ban is applied, then one recovery
    h.fake.lock().unwrap().refuse_writes = false;
    h.advance(30);
    assert_eq!(h.banned(), vec![ATTACKER]);
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 4, "{:?}", texts);
    assert!(
        texts[2].starts_with("\u{26d4} hik-f2b: 198.51.100.7 banned for "),
        "{}",
        texts[2]
    );
    assert_eq!(
        texts[3],
        format!("{}the firewall accepts bans again (after 24 h)", OK)
    );
    assert!(h.engine.alerted_problems().is_empty());
    run(&mut h, 4, 30);
    assert_eq!(telegram_texts(&h).len(), 4);
}

/// The refused bans expire while the alert is on: there is nothing left to
/// show the end of the problem. One notice says so, without claiming a
/// recovery, and there are no more reminders.
#[test]
fn refused_bans_that_expire_end_the_alert_without_a_recovery() {
    let mut h = Harness::new(true);
    h.fake.lock().unwrap().refuse_writes = true;
    util::capture_log();
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    run(&mut h, 20, 30); // 10:12:00: alerted
    assert_eq!(telegram_texts(&h).len(), 1);
    // the ban waits for bantime (24 hours), then is dropped
    h.set_host(host_of("10:02:00") + 86400 + 60);
    h.tick();
    assert_eq!(h.engine.state().ledger.waiting(), 0);
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 2, "{:?}", texts);
    assert_eq!(
        texts[1],
        "\u{2139}\u{fe0f} hik-f2b: no refused ban is waiting any more; whether the firewall \
         accepts bans is not known until the next ban (after 24 h)"
    );
    assert!(h.engine.alerted_problems().is_empty());
    let log = util::captured_log();
    assert_eq!(
        logged(
            &log,
            "INFO health unknown [ban-refused]: hik-f2b: no refused ban is waiting"
        ),
        1,
        "{:?}",
        log
    );
    assert_eq!(logged(&log, "health recovered"), 0);
    // no reminder a day later
    run(&mut h, 25, 3600);
    assert_eq!(telegram_texts(&h).len(), 2);
}

/// Without [telegram] the same events only reach the log.
#[test]
fn health_problems_without_telegram() {
    let mut h = Harness::new(false);
    h.fake.lock().unwrap().nvr_down = true;
    run(&mut h, 25, 30);
    assert_eq!(h.engine.alerted_problems(), vec!["nvr:nvr1"]);
    assert_eq!(h.engine.queued_notifications(), 0);
    assert!(h.fake.lock().unwrap().tg_sent.is_empty());
}

// ---------------------------------------------------- already-listed check

#[test]
fn already_listed_is_recognised_whatever_the_wording() {
    let mut h = Harness::with(Opts {
        general: "max_bans_per_hour = 1",
        ..Default::default()
    });
    {
        let mut f = h.fake.lock().unwrap();
        f.duplicate_text = Some("failure: entry is a duplicate".to_string());
        f.bans.push("198.51.100.4".to_string());
    }
    h.burst("10:01", "198.51.100.4", 5);
    h.burst("10:02", "198.51.100.5", 5);
    h.cycle("10:03:00");
    assert_eq!(h.banned(), vec!["198.51.100.4", "198.51.100.5"]);
    assert_eq!(h.engine.state().ledger.waiting(), 0);
    assert_eq!(
        h.fake.lock().unwrap().lookups,
        vec!["list=cctv_ban&address=198.51.100.4&.proplist=.id"]
    );
}

#[test]
fn refused_ban_of_an_unlisted_address_is_retried() {
    let mut h = Harness::new(false);
    h.fake.lock().unwrap().refuse_writes = true; // every PUT gets HTTP 400
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert!(h.banned().is_empty());
    assert_eq!(h.engine.state().ledger.waiting(), 1);
    assert_eq!(h.fake.lock().unwrap().lookups.len(), 1);
    h.fake.lock().unwrap().refuse_writes = false;
    h.advance(30);
    assert_eq!(h.banned(), vec![ATTACKER]);
}

/// HTTP 500 says nothing about the address: no lookup, and the next cycle
/// tries again.
#[test]
fn server_error_is_retried_without_a_lookup() {
    let mut h = Harness::new(false);
    h.fake.lock().unwrap().router_down = true; // every PUT gets HTTP 500
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert!(h.banned().is_empty());
    assert_eq!(h.engine.state().ledger.waiting(), 1);
    assert!(h.fake.lock().unwrap().lookups.is_empty());
}

/// The drop rule exists but does not block (wrong interface list, say): a
/// banned attacker keeps reaching the NVR every `gap` seconds, `attacks`
/// times, then stops. Returns the harness, the Telegram texts and the
/// number of "still reached the NVR" warnings.
fn bypass_run(gap: i64, attacks: i64) -> (Harness, Vec<String>, usize) {
    let mut h = Harness::new(true);
    util::capture_log();
    let burst = |h: &Harness, at: i64| {
        for i in 0..5 {
            Harness::add_at(&h.fake, &device(at + SKEW + i), ATTACKER);
        }
    };
    let t0 = h.host;
    burst(&h, t0 + 60);
    h.advance(120); // banned
    assert_eq!(h.banned(), vec![ATTACKER]);
    let banned = h.host;
    // the router lists it, the NVR still sees it
    let bursts: Vec<i64> = (1..=attacks).map(|k| banned + k * gap - 20).collect();
    let end = bursts.last().copied().unwrap_or(banned) + 1800;
    let mut next = 0;
    while h.host < end {
        let now = h.host + 30;
        while next < bursts.len() && bursts[next] + 5 <= now {
            burst(&h, bursts[next]);
            next += 1;
        }
        h.advance(30);
    }
    assert_eq!(h.engine.state().ledger.waiting(), 0);
    let warnings = logged(&util::captured_log(), "but still reached the NVR");
    let texts = telegram_texts(&h);
    (h, texts, warnings)
}

#[test]
fn a_ban_the_router_does_not_enforce_is_warned_and_alerted() {
    for gap in [30, 60, 300] {
        let (h, texts, warnings) = bypass_run(gap, 2400 / gap);
        // every burst after the first two minutes is warned about, however
        // fast the attacker comes back
        assert!(
            warnings as i64 >= 2400 / gap - 120 / gap,
            "gap {}: {} warnings",
            gap,
            warnings
        );
        let alerts: Vec<&String> = texts
            .iter()
            .filter(|t| t.contains("banned addresses still reach an NVR"))
            .collect();
        assert_eq!(alerts.len(), 1, "gap {}: {:?}", gap, texts);
        assert!(
            alerts[0].starts_with(&format!(
                "{}banned addresses still reach an NVR for 10 min: 198.51.100.7 has been in \
                 MikroTik address-list cctv_ban for ",
                WARN
            )),
            "{}",
            alerts[0]
        );
        assert!(
            alerts[0].ends_with(" and still reached nvr1"),
            "{}",
            alerts[0]
        );
        // the attacker stops (the rule is fixed): one recovery, alert_after
        // after the last one
        let last = texts.last().unwrap();
        assert!(
            last.starts_with(&format!(
                "{}banned addresses no longer reach the NVRs (after ",
                OK
            )),
            "gap {}: {:?}",
            gap,
            texts
        );
        assert!(h.engine.alerted_problems().is_empty());
        // no ban notification for an address already listed
        assert_eq!(
            texts
                .iter()
                .filter(|t| t.contains("198.51.100.7 banned"))
                .count(),
            1
        );
    }
}

/// An attacker that comes back less often than `alert_after` is warned
/// about each time, but never stays a problem long enough to be alerted.
#[test]
fn a_rare_bypass_is_warned_but_not_alerted() {
    let (h, texts, warnings) = bypass_run(900, 4);
    assert_eq!(warnings, 4);
    assert_eq!(texts.len(), 1, "only the ban: {:?}", texts);
    assert!(h.engine.alerted_problems().is_empty());
}

/// The time of the original ban is kept while the address keeps coming
/// back, also across a restart (it is in the state file).
#[test]
fn already_listed_keeps_the_time_of_the_ban() {
    let mut h = Harness::new(false);
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    let until = h.engine.state().ledger.banned_until(attacker()).unwrap();
    h.burst("10:05", ATTACKER, 5);
    h.cycle("10:06:00");
    assert_eq!(
        h.engine.state().ledger.banned_until(attacker()).unwrap(),
        until
    );
    h.restart();
    h.burst("10:08", ATTACKER, 5);
    h.cycle("10:09:00");
    assert_eq!(
        h.engine.state().ledger.banned_until(attacker()).unwrap(),
        until
    );
    // an address listed by hand counts from the first time it is seen
    h.fake.lock().unwrap().bans.push("198.51.100.8".to_string());
    h.burst("10:10", "198.51.100.8", 5);
    h.cycle("10:11:00");
    let first = h
        .engine
        .state()
        .ledger
        .banned_until(ip("198.51.100.8"))
        .unwrap();
    h.burst("10:12", "198.51.100.8", 5);
    h.cycle("10:13:00");
    assert_eq!(
        h.engine
            .state()
            .ledger
            .banned_until(ip("198.51.100.8"))
            .unwrap(),
        first
    );
}

const LISTED: &str = "INFO 198.51.100.7 is already in MikroTik address-list cctv_ban";
const BYPASSED: &str = "WARNING 198.51.100.7 is already in MikroTik address-list cctv_ban but \
                        still reached the NVR; if this repeats, check the firewall drop rule for \
                        that list";

/// A ban at 10:02:00, and five more failed logins logged at 10:02:10, after
/// the poll that banned, before the router blocked the address. hik-f2b is
/// then restarted with `bantime` changed from `from` to `to`.
fn restart_with_another_bantime(from: &str, to: &str) -> Harness {
    let mut h = Harness::with(Opts {
        telegram: true,
        general: Box::leak(format!("bantime = {}", from).into_boxed_str()),
        ..Default::default()
    });
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert_eq!(h.banned(), vec![ATTACKER]);
    h.burst("10:02", ATTACKER, 5);
    h.ini = h.ini.replace(
        &format!("bantime = {}\n", from),
        &format!("bantime = {}\n", to),
    );
    h.restart();
    h
}

/// With a shorter `bantime` the ledger forgets the remembered ban (its end
/// is further away than the new `bantime`), so the time of the ban is not
/// known. The failed logins logged just before the ban are no bypass.
#[test]
fn listed_after_a_restart_with_a_shorter_bantime_is_not_a_bypass() {
    let mut h = restart_with_another_bantime("86400", "3600");
    util::capture_log();
    h.fake.lock().unwrap().nvr_down = true;
    h.cycle("10:02:30"); // the first poll after the start reads nothing
    assert_eq!(h.engine.state().ledger.banned_until(attacker()), None);
    h.fake.lock().unwrap().nvr_down = false;
    h.cycle("10:03:00");
    let log = util::captured_log();
    assert_eq!(exactly(&log, LISTED), 1, "{:?}", log);
    assert_eq!(exactly(&log, BYPASSED), 0, "{:?}", log);
    run(&mut h, 40, 30);
    assert_eq!(telegram_texts(&h).len(), 1, "only the ban");
    assert!(h.engine.alerted_problems().is_empty());
}

/// With a longer `bantime` the ban seems to have begun before it did.
#[test]
fn listed_after_a_restart_with_a_longer_bantime_is_not_a_bypass() {
    let mut h = restart_with_another_bantime("3600", "86400");
    util::capture_log();
    h.cycle("10:02:30");
    let log = util::captured_log();
    assert_eq!(exactly(&log, LISTED), 1, "{:?}", log);
    assert_eq!(exactly(&log, BYPASSED), 0, "{:?}", log);
    run(&mut h, 40, 30);
    assert_eq!(telegram_texts(&h).len(), 1, "only the ban");
    assert!(h.engine.alerted_problems().is_empty());
}

/// With the same `bantime`, a banned address that reaches the NVR later
/// than two polls and a minute after the start is a bypass, as before.
#[test]
fn listed_after_a_restart_with_the_same_bantime_is_a_bypass_after_the_start() {
    let mut h = Harness::new(true);
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    h.restart();
    h.cycle("10:30:00");
    h.burst("10:32", ATTACKER, 5);
    util::capture_log();
    h.cycle("10:32:30");
    let log = util::captured_log();
    assert_eq!(exactly(&log, BYPASSED), 1, "{:?}", log);
    assert_eq!(exactly(&log, LISTED), 0, "{:?}", log);
}

/// A banned attacker that keeps reaching the NVR every 30 s across a
/// restart: for two polls and a minute after the start it is not taken for
/// a bypass, from the next sighting on it is, and the problem is alerted
/// `alert_after` (10 min) later.
#[test]
fn a_bypass_that_goes_on_after_a_restart_is_alerted_after_the_start() {
    let mut h = Harness::new(true);
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert_eq!(h.banned(), vec![ATTACKER]);
    h.restart();
    util::capture_log();
    let start = host_of("10:20:00");
    let mut found = Vec::new();
    for k in 0..30 {
        let at = start + 30 * k;
        for i in 0..5 {
            Harness::add_at(&h.fake, &device(at - 20 + SKEW + i), ATTACKER);
        }
        h.set_host(at);
        h.tick();
        let log = util::captured_log();
        if exactly(&log, LISTED) == 1 {
            found.push((at - start, "listed"));
        }
        if exactly(&log, BYPASSED) == 1 {
            found.push((at - start, "bypassed"));
        }
    }
    let expected: Vec<(i64, &str)> = (0..30)
        .map(|k| (30 * k, if 30 * k <= 120 { "listed" } else { "bypassed" }))
        .collect();
    assert_eq!(found, expected);
    // the first bypass at 10:22:30, alerted from 10:32:30 on
    let alerts: Vec<String> = telegram_texts(&h)
        .into_iter()
        .filter(|t| t.contains("banned addresses still reach an NVR"))
        .collect();
    assert_eq!(alerts.len(), 1, "{:?}", alerts);
    assert!(
        alerts[0].starts_with(&format!(
            "{}banned addresses still reach an NVR for 10 min: 198.51.100.7 has been in \
             MikroTik address-list cctv_ban for ",
            WARN
        )),
        "{}",
        alerts[0]
    );
    assert_eq!(h.engine.alerted_problems(), vec!["ban-bypassed"]);
}

#[test]
fn todays_wording_needs_no_lookup() {
    let mut h = Harness::new(false);
    h.fake.lock().unwrap().bans.push(ATTACKER.to_string());
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert_eq!(h.engine.state().ledger.waiting(), 0);
    assert!(h.fake.lock().unwrap().lookups.is_empty());
}

// ---------------------------------------------------------- own addresses

/// The address the host reaches the fakes from in these tests (the fakes
/// themselves are on loopback, which is never banned anyway).
const OWN: &str = "192.0.2.200";

fn with_own(opts: Opts) -> Harness {
    Harness::with(Opts {
        own: ip(OWN),
        ..opts
    })
}

/// The NVR rejects hik-f2b's login for ten minutes (its password was
/// changed on the NVR), and logs each refused login as a failed login from
/// the host's address with hik-f2b's user name. Then the password is right
/// again and hik-f2b reads those entries. Returns the harness and the log
/// from the start.
fn own_wrong_password(own: &str) -> (Harness, Vec<String>) {
    let mut h = Harness::with(Opts {
        general: "auth_backoff = 60",
        own: ip(own),
        ..Default::default()
    });
    util::capture_log();
    h.fake.lock().unwrap().nvr_auth_ok = false;
    for _ in 0..20 {
        let before = h.fake.lock().unwrap().refused_logins;
        h.advance(30);
        let refused = h.fake.lock().unwrap().refused_logins - before;
        for k in 0..refused {
            let at = device(h.host + SKEW + k as i64);
            Harness::entry_to(&h.fake, &at, "192.0.2.200", b"f2b", "illlegealAccess");
        }
    }
    let logged_entries = h.fake.lock().unwrap().entries.len();
    assert!(logged_entries >= 10, "{}", logged_entries);
    h.fake.lock().unwrap().nvr_auth_ok = true;
    run(&mut h, 4, 30);
    (h, util::captured_log())
}

/// Layer 1, the scenario it is for: hik-f2b's own failed logins are never
/// counted, and each one says why and what to check.
#[test]
fn own_failed_logins_after_a_wrong_password_are_not_counted() {
    let (h, log) = own_wrong_password(OWN);
    let entries = h.fake.lock().unwrap().entries.len();
    assert!(h.banned().is_empty());
    assert_eq!(h.engine.state().ledger.waiting(), 0);
    assert_eq!(h.fails(OWN), 0);
    assert_eq!(
        exactly(
            &log,
            "INFO nvr1: failed login from 192.0.2.200 (user=\"f2b\"): an own address of \
             hik-f2b, never banned, not counted; if that is hik-f2b's user, the NVR rejected \
             hik-f2b's own login: check its password"
        ),
        entries,
        "{:?}",
        log
    );
    assert_eq!(
        logged(&log, "failed login from 192.0.2.200 (user=\"f2b\") at "),
        0
    );
    assert!(logged(&log, "ERROR nvr1: login to the NVR was rejected") >= 10);
    // the same log from an address that is not an own address is banned:
    // the scenario reaches maxretry
    let (h, _) = own_wrong_password("127.0.0.1");
    assert_eq!(h.banned(), vec![OWN]);
}

/// A forged log entry cannot get an own address banned, whatever user name
/// it names.
#[test]
fn a_forged_entry_with_an_own_address_is_not_counted() {
    let mut h = with_own(Opts::default());
    util::capture_log();
    for s in 0..8 {
        h.add_full(
            &format!("10:01:{:02}", 10 + s),
            OWN,
            "admin",
            "illlegealAccess",
        );
    }
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    let log = util::captured_log();
    assert_eq!(h.banned(), vec![ATTACKER]);
    assert_eq!(h.fails(OWN), 0);
    assert_eq!(
        logged(
            &log,
            "INFO nvr1: failed login from 192.0.2.200 (user=\"admin\"): an own address of hik-f2b"
        ),
        8,
        "{:?}",
        log
    );
    // the router is asked about the own address once per firewall check,
    // never asked to ban it
    let f = h.fake.lock().unwrap();
    assert!(f.put_log.iter().all(|(a, _)| a != OWN), "{:?}", f.put_log);
}

/// An address that becomes an own address (DHCP gave it to the host) while
/// its ban waits: the waiting ban and its counted failed logins are
/// dropped before bans are attempted, with one INFO line for the change.
#[test]
fn an_address_that_becomes_an_own_address_has_its_waiting_ban_dropped() {
    const NEXT: &str = "198.51.100.9";
    let mut h = with_own(Opts::default());
    h.fake.lock().unwrap().router_unreachable = true;
    h.burst("10:01", ATTACKER, 5);
    h.add("10:01:30", NEXT);
    h.cycle("10:02:00");
    assert!(h.engine.state().ledger.is_waiting(attacker()));
    assert_eq!(h.fails(NEXT), 1);
    util::capture_log();
    h.own.set_local(Ok(attacker()));
    h.advance(30);
    let log = util::captured_log();
    assert_eq!(
        exactly(
            &log,
            "INFO own addresses changed: added 198.51.100.7, removed 192.0.2.200; now router \
             127.0.0.1 from 198.51.100.7, nvr1 127.0.0.1 from 198.51.100.7"
        ),
        1,
        "{:?}",
        log
    );
    assert_eq!(
        exactly(
            &log,
            "INFO 198.51.100.7: waiting ban dropped, 5 counted failed login(s) forgotten: the \
             address is now an own address of hik-f2b and is never banned"
        ),
        1,
        "{:?}",
        log
    );
    assert!(!h.engine.state().ledger.is_waiting(attacker()));
    // an address that is not an own address keeps its count
    assert_eq!(h.fails(NEXT), 1);
    h.fake.lock().unwrap().router_unreachable = false;
    h.own.set_local(Ok(ip(NEXT)));
    util::capture_log();
    h.advance(30);
    let log = util::captured_log();
    assert_eq!(
        exactly(
            &log,
            "INFO 198.51.100.9: 1 counted failed login(s) forgotten: the address is now an own \
             address of hik-f2b and is never banned"
        ),
        1,
        "{:?}",
        log
    );
    // the address that is no longer an own address is not banned for what
    // was dropped
    assert!(h.banned().is_empty());
    assert_eq!(h.engine.state().ledger.waiting(), 0);
}

/// The start of the service logs the own addresses; a look-up that fails
/// keeps the last known addresses and is said once.
#[test]
fn the_own_addresses_are_logged_at_the_start_and_when_a_look_up_fails() {
    let mut h = with_own(Opts::default());
    util::capture_log();
    h.engine.startup_own();
    assert_eq!(
        util::captured_log(),
        vec![
            "INFO own addresses, never banned: router 127.0.0.1 from 192.0.2.200, nvr1 \
             127.0.0.1 from 192.0.2.200"
        ]
    );
    h.own.set_local(Err("no route to 127.0.0.1".to_string()));
    h.advance(30);
    h.advance(30);
    let log = util::captured_log();
    assert_eq!(
        log.iter()
            .filter(|l| l.contains("own addresses"))
            .collect::<Vec<_>>(),
        vec![
            "WARNING own addresses: the look-up for router failed, its last known addresses \
             stay: no route to 127.0.0.1",
            "WARNING own addresses: the look-up for nvr1 failed, its last known addresses stay: \
             no route to 127.0.0.1",
        ]
    );
    // still an own address
    h.add_full("10:01:10", OWN, "admin", "illlegealAccess");
    h.advance(30);
    assert_eq!(h.fails(OWN), 0);
    // a start with the look-up failing names what is missing
    let mut h = Harness::build(Opts {
        own: ip(OWN),
        ..Default::default()
    });
    h.own.set_local(Err("no route".to_string()));
    h.restart();
    util::capture_log();
    h.engine.startup_own();
    assert_eq!(
        util::captured_log(),
        vec![
            "INFO own addresses, never banned: router 127.0.0.1, nvr1 127.0.0.1",
            "WARNING own addresses: a look-up failed, it is tried again in every poll (a host \
             name every 5 min): router: no route; nvr1: no route",
        ]
    );
}

/// `--check` prints the own addresses; a failed look-up is a failed check.
#[test]
fn check_prints_the_own_addresses() {
    use hik_f2b::health::Status;
    let h = with_own(Opts::default());
    let line = h
        .check()
        .into_iter()
        .find(|l| l.item == "own addresses")
        .unwrap();
    assert_eq!(
        line.to_string(),
        "ok       own addresses: router 127.0.0.1 from 192.0.2.200, nvr1 127.0.0.1 from \
         192.0.2.200 (never banned)"
    );
    h.own.set_local(Err("no route".to_string()));
    let line = h
        .check()
        .into_iter()
        .find(|l| l.item == "own addresses")
        .unwrap();
    assert_eq!(line.status, Status::Failed);
    assert_eq!(
        line.to_string(),
        "FAILED   own addresses: router 127.0.0.1, nvr1 127.0.0.1; look-up failed: router: no \
         route; nvr1: no route"
    );
}

/// Layer 3: an own address in the address-list (put there by hand, by
/// another tool or by an earlier version) is removed at the next firewall
/// check, with a WARNING and a notification at once. One look-up per own
/// address outside the reserved ranges and firewall check, no more.
#[test]
fn an_own_address_in_the_address_list_is_removed_and_reported_at_once() {
    let mut h = with_own(Opts {
        telegram: true,
        ..Default::default()
    });
    // the first poll ran the first periodic check: one look-up, for the one
    // own address that is not loopback
    let lookup = format!("list=cctv_ban&address={}&.proplist=.id", OWN);
    assert_eq!(h.fake.lock().unwrap().lookups, vec![lookup.clone()]);
    h.fake.lock().unwrap().bans.push(OWN.to_string());
    run(&mut h, 9, 30); // the next check is due 300 s after the first
    assert_eq!(h.banned(), vec![OWN]);
    assert_eq!(h.fake.lock().unwrap().lookups.len(), 1);
    util::capture_log();
    h.advance(30);
    let log = util::captured_log();
    assert_eq!(
        exactly(
            &log,
            "WARNING 192.0.2.200 is an own address of hik-f2b and was in MikroTik address-list \
             cctv_ban: the entry is removed"
        ),
        1,
        "{:?}",
        log
    );
    assert!(h.banned().is_empty());
    {
        let f = h.fake.lock().unwrap();
        assert_eq!(f.delete_log, vec![(OWN.to_string(), "removed")]);
        assert_eq!(f.lookups, vec![lookup.clone(), lookup.clone()]);
    }
    assert_eq!(
        telegram_texts(&h),
        vec![format!(
            "{}192.0.2.200 is an own address of hik-f2b and was in MikroTik address-list \
             cctv_ban; the entry is removed. hik-f2b never bans its own addresses: it was added \
             by hand, by another tool or by an earlier version.",
            WARN
        )]
    );
    assert!(h.engine.alerted_problems().is_empty());
    // the check at the start of the service does it too
    h.fake.lock().unwrap().bans.push(OWN.to_string());
    h.restart();
    assert!(h.engine.startup_check(h.host as u64));
    assert!(h.banned().is_empty());
    h.advance(30);
    assert_eq!(telegram_texts(&h).len(), 2);
    // nothing listed: nothing removed, nothing sent
    run(&mut h, 20, 30);
    assert_eq!(telegram_texts(&h).len(), 2);
    assert_eq!(h.fake.lock().unwrap().delete_log.len(), 2);
}

/// A removal that the router refuses opens `own-address-listed`, reported
/// once at once and alerted after `alert_after`; a later removal ends it.
#[test]
fn a_removal_that_fails_is_a_health_problem_until_the_address_is_gone() {
    let mut h = with_own(Opts {
        telegram: true,
        general: "alert_after = 60",
        ..Default::default()
    });
    {
        let mut f = h.fake.lock().unwrap();
        f.bans.push(OWN.to_string());
        f.refuse_writes = true;
    }
    util::capture_log();
    run(&mut h, 10, 30); // the check at 10:05:00 finds it
    let log = util::captured_log();
    assert_eq!(
        exactly(
            &log,
            "ERROR cannot remove own address 192.0.2.200 from MikroTik address-list cctv_ban, \
             will retry at the next firewall check: refused: HTTP 400: {\"detail\":\"not enough \
             permissions (9)\",\"error\":400,\"message\":\"Bad Request\"}"
        ),
        1,
        "{:?}",
        log
    );
    // reported at once
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 1, "{:?}", texts);
    assert!(h.engine.alerted_problems().is_empty());
    // and alerted after alert_after
    run(&mut h, 2, 30);
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 2, "{:?}", texts);
    assert_eq!(
        texts[0],
        format!(
            "{}192.0.2.200 is an own address of hik-f2b and is in MikroTik address-list \
             cctv_ban, and cannot be removed: refused: HTTP 400: {{\"detail\":\"not enough \
             permissions (9)\",\"error\":400,\"message\":\"Bad Request\"}}. Remove it by hand.",
            WARN
        )
    );
    assert!(
        texts[1].starts_with(&format!(
            "{}an own address of hik-f2b is in the address-list and cannot be removed for 1 \
             min: 192.0.2.200 is in MikroTik address-list cctv_ban; remove it by hand and check \
             that the router user may write: refused: HTTP 400",
            WARN
        )),
        "{}",
        texts[1]
    );
    assert_eq!(h.engine.alerted_problems(), vec!["own-address-listed"]);
    // the next checks try again, without a second message
    run(&mut h, 10, 30);
    assert_eq!(telegram_texts(&h).len(), 2);
    assert_eq!(h.banned(), vec![OWN]);
    assert_eq!(h.engine.alerted_problems(), vec!["own-address-listed"]);
    // the router user may write again
    h.fake.lock().unwrap().refuse_writes = false;
    run(&mut h, 10, 30);
    assert!(h.banned().is_empty());
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 4, "{:?}", texts);
    assert!(texts[2].contains("the entry is removed"), "{}", texts[2]);
    assert!(
        texts[3].starts_with(&format!(
            "{}no own address of hik-f2b is in the address-list any more (after ",
            OK
        )),
        "{}",
        texts[3]
    );
    assert!(h.engine.alerted_problems().is_empty());
    // the entry gone by itself (it timed out) also ends the problem
    {
        let mut f = h.fake.lock().unwrap();
        f.bans.push(OWN.to_string());
        f.refuse_writes = true;
    }
    run(&mut h, 14, 30);
    assert_eq!(h.engine.alerted_problems(), vec!["own-address-listed"]);
    h.fake.lock().unwrap().bans.clear();
    run(&mut h, 10, 30);
    assert!(h.engine.alerted_problems().is_empty());
    assert!(telegram_texts(&h)
        .last()
        .unwrap()
        .contains("no own address of hik-f2b is in the address-list any more"));
}

/// A dry run reports an own address in the address-list once and removes
/// nothing; notify-only mode asks no router.
#[test]
fn own_address_in_the_address_list_in_a_dry_run_and_in_notify_only_mode() {
    let mut h = with_own(Opts {
        telegram: true,
        general: "dry_run = true",
        ..Default::default()
    });
    h.fake.lock().unwrap().bans.push(OWN.to_string());
    util::capture_log();
    run(&mut h, 25, 30); // two checks
    let log = util::captured_log();
    assert_eq!(
        exactly(
            &log,
            "WARNING DRY RUN: 192.0.2.200 is an own address of hik-f2b and is in MikroTik \
             address-list cctv_ban: it would be removed"
        ),
        1,
        "{:?}",
        log
    );
    assert_eq!(h.banned(), vec![OWN]);
    assert!(h.fake.lock().unwrap().delete_log.is_empty());
    assert_eq!(h.fake.lock().unwrap().lookups.len(), 3);
    assert_eq!(
        telegram_texts(&h),
        vec![format!(
            "{}192.0.2.200 is an own address of hik-f2b and is in MikroTik address-list \
             cctv_ban. Dry run: it is not removed; remove it by hand.",
            WARN
        )]
    );
    assert!(h.engine.alerted_problems().is_empty());
    // once it is gone and listed again, it is reported again
    h.fake.lock().unwrap().bans.clear();
    run(&mut h, 10, 30);
    h.fake.lock().unwrap().bans.push(OWN.to_string());
    run(&mut h, 10, 30);
    assert_eq!(telegram_texts(&h).len(), 2);

    // notify-only mode: no router to ask; own failed logins still do not count
    let mut h = with_own(Opts {
        telegram: true,
        mikrotik: false,
        ..Default::default()
    });
    h.burst("10:01", OWN, 6);
    run(&mut h, 25, 30);
    assert_eq!(h.fake.lock().unwrap().router_requests, 0);
    assert_eq!(h.fails(OWN), 0);
    assert!(telegram_texts(&h).is_empty());
}

// ------------------------------------------------------- names in ignoreip

/// The administrator's dynamic DNS name, and the addresses it resolves to
/// in these tests.
const HOME: &str = "home.example.net";
const HOME_IP: &str = "203.0.113.7";
const NEXT_IP: &str = "203.0.113.8";
const WITH_HOME: &str = "ignoreip = 192.168.0.0/16, home.example.net";

fn with_home(opts: Opts) -> Harness {
    Harness::with(Opts {
        general: WITH_HOME,
        own: ip(OWN),
        names: &[(HOME, &[HOME_IP])],
        ..opts
    })
}

/// The administrator's scenario, from start to end: wrong passwords from
/// the address the name resolves to are never counted; the name then
/// follows the administrator to a new address, whose waiting ban is
/// dropped, and the old address is banned on its next failed logins.
#[test]
fn an_administrator_behind_an_ignoreip_name_is_never_banned() {
    let mut h = with_home(Opts::default());
    util::capture_log();
    h.engine.startup_names();
    assert_eq!(
        util::captured_log(),
        vec!["INFO ignoreip names, never banned: home.example.net 203.0.113.7"]
    );
    // eight wrong passwords from home, and an attacker
    h.burst("10:01", HOME_IP, 8);
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    let log = util::captured_log();
    assert_eq!(h.banned(), vec![ATTACKER]);
    assert_eq!(h.fails(HOME_IP), 0);
    assert_eq!(
        exactly(
            &log,
            "INFO nvr1: failed login from 203.0.113.7 (user=\"admin\"): never banned (ignoreip \
             name home.example.net), not counted"
        ),
        8,
        "{:?}",
        log
    );
    // the administrator's next address has failed logins before the name
    // follows it, while the router cannot be reached: its ban waits
    h.fake.lock().unwrap().router_unreachable = true;
    h.burst("10:03", NEXT_IP, 5);
    h.cycle("10:04:00");
    assert!(h.engine.state().ledger.is_waiting(ip(NEXT_IP)));
    // the name follows; its answer is looked up again 5 min after the first
    // poll, not before
    h.own.set_name(HOME, Ok(vec![ip(NEXT_IP)]));
    h.cycle("10:04:59");
    assert!(h.engine.state().ledger.is_waiting(ip(NEXT_IP)));
    util::capture_log();
    h.cycle("10:05:00");
    let log = util::captured_log();
    assert_eq!(
        exactly(
            &log,
            "INFO ignoreip: home.example.net now resolves to 203.0.113.8 (was 203.0.113.7)"
        ),
        1,
        "{:?}",
        log
    );
    assert_eq!(
        exactly(
            &log,
            "INFO 203.0.113.8: waiting ban dropped, 5 counted failed login(s) forgotten: the \
             address is now what the ignoreip name home.example.net resolves to and is never \
             banned"
        ),
        1,
        "{:?}",
        log
    );
    assert!(!h.engine.state().ledger.is_waiting(ip(NEXT_IP)));
    // the router is back: nothing is banned for what was dropped
    h.fake.lock().unwrap().router_unreachable = false;
    h.cycle("10:05:30");
    assert_eq!(h.banned(), vec![ATTACKER]);
    // the old address is exempt no more: its next failed logins are counted
    // from nothing and banned; the new one is exempt
    util::capture_log();
    h.burst("10:06", HOME_IP, 5);
    h.burst("10:06", NEXT_IP, 5);
    h.cycle("10:07:00");
    let log = util::captured_log();
    assert_eq!(h.banned(), vec![ATTACKER, HOME_IP]);
    assert_eq!(h.fails(NEXT_IP), 0);
    assert_eq!(
        exactly(
            &log,
            "INFO nvr1: failed login from 203.0.113.7 (user=\"admin\") at 2026-01-10T08:06:10Z \
             [1/5]"
        ),
        1,
        "{:?}",
        log
    );
    assert_eq!(
        exactly(
            &log,
            "INFO nvr1: failed login from 203.0.113.8 (user=\"admin\"): never banned (ignoreip \
             name home.example.net), not counted"
        ),
        5,
        "{:?}",
        log
    );
}

/// A resolver that fails at the start: the name exempts nothing, which the
/// start says once, and no poll says it again. Once the name resolves (at
/// its next look-up, 5 min after the first poll), its address is exempt
/// and what was counted of it is forgotten.
#[test]
fn an_ignoreip_name_that_does_not_resolve_at_the_start_exempts_nothing_until_it_does() {
    let mut h = Harness::build(Opts {
        general: WITH_HOME,
        own: ip(OWN),
        ..Default::default()
    });
    util::capture_log();
    h.engine.startup_names();
    assert_eq!(
        util::captured_log(),
        vec![
            "INFO ignoreip names, never banned: home.example.net not resolved",
            "WARNING ignoreip: home.example.net does not resolve, so it exempts no address until \
             it does; it is tried again every 5 min: cannot resolve home.example.net: no such \
             name",
        ]
    );
    h.tick(); // the first poll, at 10:00:00
    h.burst("10:01", HOME_IP, 3);
    h.cycle("10:02:00");
    assert_eq!(h.fails(HOME_IP), 3);
    h.own.set_name(HOME, Ok(vec![ip(HOME_IP)]));
    h.cycle("10:04:59");
    assert_eq!(h.fails(HOME_IP), 3);
    h.cycle("10:05:00");
    assert_eq!(h.fails(HOME_IP), 0);
    let log = util::captured_log();
    assert_eq!(
        log.iter()
            .filter(|l| l.contains("ignoreip"))
            .collect::<Vec<_>>(),
        vec![
            "INFO ignoreip: home.example.net now resolves to 203.0.113.7 (was none)",
            "INFO 203.0.113.7: 3 counted failed login(s) forgotten: the address is now what the \
             ignoreip name home.example.net resolves to and is never banned",
        ]
    );
    h.burst("10:06", HOME_IP, 5);
    h.cycle("10:07:00");
    assert_eq!(h.fails(HOME_IP), 0);
    assert!(h.banned().is_empty());
}

/// `--check` prints what each name resolves to now, one line per name; a
/// name that does not resolve is a failed check.
#[test]
fn check_prints_what_each_ignoreip_name_resolves_to() {
    use hik_f2b::health::Status;
    let h = Harness::build(Opts {
        general: "ignoreip = 192.168.0.0/16, home.example.net, vpn.example.org",
        own: ip(OWN),
        names: &[(HOME, &[NEXT_IP, HOME_IP])],
        ..Default::default()
    });
    let lines = h.check();
    let text: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
    assert_eq!(
        text[1..],
        [
            "ok       nvr nvr1 log: order not known, page size not known (0 entries read from \
             the last 24 h)",
            "ok       firewall: 1 enabled rule(s) in /ip/firewall/raw with \
             src-address-list=cctv_ban",
            "ok       own addresses: router 127.0.0.1 from 192.0.2.200, nvr1 127.0.0.1 from \
             192.0.2.200 (never banned)",
            "ok       ignoreip home.example.net: resolves to 203.0.113.7 and 203.0.113.8 (never \
             banned)",
            "FAILED   ignoreip vpn.example.org: does not resolve, so it exempts no address: \
             cannot resolve vpn.example.org: no such name",
            "off      telegram: not configured",
            "off      country database: not configured",
        ],
        "{:#?}",
        text
    );
    assert!(
        text[0].starts_with("ok       nvr nvr1: login accepted"),
        "{}",
        text[0]
    );
    assert_eq!(
        lines.iter().filter(|l| l.status == Status::Failed).count(),
        1
    );
    // without a name, no such line
    let h = with_own(Opts::default());
    assert!(!h.check().iter().any(|l| l.item.starts_with("ignoreip")));
}

/// An address that a name of `ignoreip` resolves to is not an own address:
/// found in the address-list, it is not removed (hik-f2b removes a ban only
/// for an own address, ADR 0005), the router is not even asked about it,
/// and it never goes into the safe list.
#[test]
fn an_address_of_an_ignoreip_name_in_the_address_list_is_not_removed() {
    let mut h = with_home(Opts {
        mikrotik_extra: "safe_list = cctv_safe",
        ..Default::default()
    });
    h.fake.lock().unwrap().bans.push(HOME_IP.to_string());
    h.burst("10:01", HOME_IP, 6);
    run(&mut h, 25, 30); // two firewall checks after the first
    assert_eq!(h.banned(), vec![HOME_IP]);
    assert_eq!(h.fails(HOME_IP), 0);
    let f = h.fake.lock().unwrap();
    assert!(f.delete_log.is_empty(), "{:?}", f.delete_log);
    // every look-up in a list is for the own address: one in the
    // address-list and one in the safe list per check
    assert_eq!(f.lookups.len(), 6, "{:?}", f.lookups);
    assert!(
        f.lookups
            .iter()
            .all(|l| l.contains(&format!("&address={}&", OWN))),
        "{:?}",
        f.lookups
    );
    assert!(!f.safe_log.is_empty());
    assert!(
        f.safe_log.iter().all(|(_, address, _)| address == OWN),
        "{:?}",
        f.safe_log
    );
    assert!(f.listed.iter().all(|e| e.address == OWN), "{:?}", f.listed);
}

// --------------------------------------------------------------- safe list

/// The requests of one firewall check that the router answers, without a
/// safe list, as they were before the safe list existed: the drop rule in
/// `raw`, and the look-up of the own address in the address-list.
const CHECK_REQUESTS: [&str; 2] = [
    "GET /rest/ip/firewall/raw?src-address-list=cctv_ban&.proplist=.id%2Cdisabled%2Cinvalid",
    "GET /rest/ip/firewall/address-list?list=cctv_ban&address=192.0.2.200&.proplist=.id",
];

/// A harness with the safe list `cctv_safe`, its rule above the drop rule
/// in `raw`, the own address `OWN`, and `general` in `[general]`; the
/// engine has not checked or polled yet.
fn with_safe_list(general: &'static str) -> Harness {
    let h = Harness::build(Opts {
        own: ip(OWN),
        telegram: true,
        general,
        mikrotik_extra: "safe_list = cctv_safe",
        ..Default::default()
    });
    h.fake.lock().unwrap().rules = vec![
        Rule::accept("raw", "cctv_safe"),
        Rule::new("raw", "cctv_ban", false),
    ];
    h
}

/// The requests that reached the router since the last call.
fn requests(h: &Harness) -> Vec<String> {
    std::mem::take(&mut h.fake.lock().unwrap().rest_log)
}

/// What was written to the safe list since the last call.
fn safe_writes(h: &Harness) -> Vec<(String, String, &'static str)> {
    std::mem::take(&mut h.fake.lock().unwrap().safe_log)
}

fn safe(outcome: &'static str) -> (String, String, &'static str) {
    ("cctv_safe".to_string(), OWN.to_string(), outcome)
}

/// Without `safe_list`, a firewall check sends what it sent before the
/// safe list existed, at startup and in a cycle, and nothing about another
/// list.
#[test]
fn without_a_safe_list_no_request_is_added() {
    let mut h = Harness::build(Opts {
        own: ip(OWN),
        ..Default::default()
    });
    assert!(h.engine.startup_check(h.host as u64));
    assert_eq!(requests(&h), CHECK_REQUESTS);
    // the first poll: the next check is due 300 s after the first
    run(&mut h, 10, 30);
    assert_eq!(requests(&h), CHECK_REQUESTS);
    run(&mut h, 30, 30);
    assert_eq!(
        requests(&h),
        [CHECK_REQUESTS, CHECK_REQUESTS, CHECK_REQUESTS].concat()
    );
    let f = h.fake.lock().unwrap();
    assert!(f.safe_log.is_empty() && f.listed.is_empty());
}

/// The own address toward the router is written at startup, with a
/// timeout of six firewall checks, and renewed at each check: four
/// requests more per check.
#[test]
fn the_safe_list_is_written_at_startup_and_renewed_at_each_check() {
    let mut h = with_safe_list("");
    util::capture_log();
    assert!(h.engine.startup_check(h.host as u64));
    assert_eq!(
        util::captured_log(),
        vec![
            "INFO firewall check ok: 1 enabled rule(s) in /ip/firewall/raw with \
             src-address-list=cctv_ban",
            "INFO safe list check ok: 1 enabled accept rule(s) in /ip/firewall/raw with \
             src-address-list=cctv_safe before the drop rule for cctv_ban",
            "INFO 192.0.2.200 added to the safe list cctv_safe for 00:30:00",
        ]
    );
    let check = [
        CHECK_REQUESTS[0],
        "GET /rest/ip/firewall/raw?.proplist=.id",
        "GET /rest/ip/firewall/raw?src-address-list=cctv_safe&.proplist=.id%2Cdisabled%2Cinvalid%2Caction",
        "GET /rest/ip/firewall/address-list?list=cctv_safe&address=192.0.2.200&.proplist=.id%2Cdynamic%2Ctimeout",
    ];
    let added = [
        &check[..],
        &["PUT /rest/ip/firewall/address-list?", CHECK_REQUESTS[1]],
    ]
    .concat();
    assert_eq!(requests(&h), added);
    assert_eq!(safe_writes(&h), vec![safe("added")]);
    {
        let f = h.fake.lock().unwrap();
        assert_eq!(
            f.listed,
            vec![Listed {
                list: "cctv_safe".to_string(),
                address: OWN.to_string(),
                timeout: Some("00:30:00".to_string()),
            }]
        );
        // nothing of it went to the address-list
        assert!(f.ban_bodies.is_empty() && f.put_log.is_empty());
    }
    // the polls between two checks send nothing to the router
    run(&mut h, 9, 30);
    assert!(requests(&h).is_empty());
    // the periodic check renews it
    h.fake.lock().unwrap().listed[0].timeout = Some("00:25:00".to_string());
    h.advance(30);
    // the id of the entry, as the fake router makes it
    let patch = format!(
        "PATCH /rest/ip/firewall/address-list/*1{:08X}?",
        u32::from(ip(OWN))
    );
    let renewed = [&check[..], &[patch.as_str(), CHECK_REQUESTS[1]]].concat();
    assert_eq!(requests(&h), renewed);
    assert_eq!(safe_writes(&h), vec![safe("renewed")]);
    let f = h.fake.lock().unwrap();
    assert_eq!(f.listed.len(), 1);
    assert_eq!(f.listed[0].timeout.as_deref(), Some("00:30:00"));
    drop(f);
    assert!(h.engine.alerted_problems().is_empty());
    assert!(telegram_texts(&h).is_empty());
}

/// An entry that is there already is renewed, never added a second time;
/// one without a timeout (added by hand) is left as it is.
#[test]
fn an_existing_entry_is_renewed_not_duplicated() {
    let mut h = with_safe_list("");
    h.fake.lock().unwrap().listed.push(Listed {
        list: "cctv_safe".to_string(),
        address: OWN.to_string(),
        timeout: Some("00:01:00".to_string()),
    });
    assert!(h.engine.startup_check(h.host as u64));
    run(&mut h, 20, 30);
    assert_eq!(safe_writes(&h), vec![safe("renewed"); 3]);
    assert_eq!(h.fake.lock().unwrap().listed.len(), 1);
    // static: no write at all
    requests(&h);
    h.fake.lock().unwrap().listed[0].timeout = None;
    run(&mut h, 20, 30);
    assert!(safe_writes(&h).is_empty());
    let f = h.fake.lock().unwrap();
    assert_eq!(f.listed.len(), 1);
    assert_eq!(f.listed[0].timeout, None);
    assert!(!f
        .rest_log
        .iter()
        .any(|r| r.starts_with("PUT") || r.starts_with("PATCH")));
}

/// A new own address toward the router is written at the next check; the
/// old entry is left to expire, not removed.
#[test]
fn a_new_own_address_is_written_and_the_old_one_left_to_expire() {
    let mut h = with_safe_list("");
    assert!(h.engine.startup_check(h.host as u64));
    h.tick();
    h.own.set_local(Ok(ip("192.0.2.201")));
    run(&mut h, 9, 30);
    util::capture_log();
    h.advance(30);
    let log = util::captured_log();
    for line in [
        "INFO 192.0.2.200 is no longer the own address toward the router: its entry in the safe \
         list cctv_safe is left to expire",
        "INFO 192.0.2.201 added to the safe list cctv_safe for 00:30:00",
    ] {
        assert_eq!(exactly(&log, line), 1, "{:?}", log);
    }
    let f = h.fake.lock().unwrap();
    let listed: Vec<&str> = f.listed.iter().map(|e| e.address.as_str()).collect();
    assert_eq!(listed, ["192.0.2.200", "192.0.2.201"]);
    assert!(f.delete_log.is_empty());
    drop(f);
    // said once
    util::capture_log();
    run(&mut h, 10, 30);
    assert_eq!(
        starting(&util::captured_log(), "INFO 192.0.2.200 is no longer"),
        0
    );
    let writes = safe_writes(&h);
    assert_eq!(
        writes.last(),
        Some(&(
            "cctv_safe".to_string(),
            "192.0.2.201".to_string(),
            "renewed"
        ))
    );
}

/// A write the router refuses is an ERROR at each check and the health
/// problem `safe-list-refused`, which a write that works ends. A write that
/// meets a router error is the firewall problem, as for a ban.
#[test]
fn a_refused_write_is_its_own_health_problem() {
    let mut h = with_safe_list("alert_after = 60");
    h.fake.lock().unwrap().refuse_writes = true;
    util::capture_log();
    assert!(h.engine.startup_check(h.host as u64));
    let refused = "ERROR cannot write own address 192.0.2.200 to the safe list cctv_safe, will \
                   retry at the next firewall check: refused: HTTP 400: {\"detail\":\"not enough \
                   permissions (9)\",\"error\":400,\"message\":\"Bad Request\"}";
    assert_eq!(exactly(&util::captured_log(), refused), 1);
    run(&mut h, 10, 30);
    let log = util::captured_log();
    assert_eq!(exactly(&log, refused), 1, "{:?}", log);
    assert_eq!(
        exactly(
            &log,
            "ERROR health alert [safe-list-refused]: hik-f2b: the firewall refuses to write the \
             own address to the safe list for 1 min: 192.0.2.200 cannot be written to cctv_safe: \
             refused: HTTP 400: {\"detail\":\"not enough \
             permissions (9)\",\"error\":400,\"message\":\"Bad Request\"}"
        ),
        1,
        "{:?}",
        log
    );
    assert_eq!(h.engine.alerted_problems(), vec!["safe-list-refused"]);
    assert_eq!(safe_writes(&h), vec![safe("refused"); 2]);
    // the write works
    h.fake.lock().unwrap().refuse_writes = false;
    run(&mut h, 10, 30);
    assert_eq!(
        exactly(
            &util::captured_log(),
            "INFO health recovered [safe-list-refused]: hik-f2b: the firewall writes the own \
             address to the safe list again (after 10 min)"
        ),
        1
    );
    assert!(h.engine.alerted_problems().is_empty());
    assert_eq!(h.fake.lock().unwrap().listed.len(), 1);
    // a router error on the write: the firewall problem
    h.fake.lock().unwrap().listed.clear();
    h.fake.lock().unwrap().put_status = Some(500);
    run(&mut h, 12, 30);
    assert_eq!(h.engine.alerted_problems(), vec!["firewall"]);
    h.fake.lock().unwrap().put_status = None;
    run(&mut h, 10, 30);
    assert!(h.engine.alerted_problems().is_empty());
}

/// The rule is missing: an ERROR at startup, a WARNING at each check, the
/// health problem `safe-list-rule` after `alert_after`; the rule is added
/// and the problem ends. The safe list is written either way.
#[test]
fn a_missing_safe_list_rule_is_a_problem_until_it_is_added() {
    let mut h = with_safe_list("alert_after = 60");
    h.fake.lock().unwrap().rules = vec![Rule::new("raw", "cctv_ban", false)];
    let reason = "no rule in /ip/firewall/raw has src-address-list=cctv_safe: add one with \
                  action=accept above the drop rule for cctv_ban, in the same table";
    util::capture_log();
    assert!(h.engine.startup_check(h.host as u64));
    let log = util::captured_log();
    assert_eq!(
        exactly(&log, &format!("ERROR safe list check failed: {}", reason)),
        1,
        "{:?}",
        log
    );
    assert_eq!(safe_writes(&h), vec![safe("added")]);
    run(&mut h, 10, 30);
    let log = util::captured_log();
    assert_eq!(
        exactly(&log, &format!("WARNING safe list check failed: {}", reason)),
        1,
        "{:?}",
        log
    );
    assert_eq!(h.engine.alerted_problems(), vec!["safe-list-rule"]);
    let texts = telegram_texts(&h);
    assert_eq!(
        texts,
        vec![format!(
            "{}the safe list does not keep the own address from being blocked for 1 min: {}",
            WARN, reason
        )]
    );
    // the operator adds the rule above the drop rule
    h.fake
        .lock()
        .unwrap()
        .rules
        .insert(0, Rule::accept("raw", "cctv_safe"));
    run(&mut h, 10, 30);
    assert!(h.engine.alerted_problems().is_empty());
    assert_eq!(
        telegram_texts(&h)[1],
        format!(
            "{}the safe list keeps the own address from being blocked again (after 10 min)",
            OK
        )
    );
}

/// The rule check on the router's answers, in every case: the rule must
/// be in the table of the first usable drop rule, enabled, valid, with the
/// action `accept`, and come before that drop rule in the table's order,
/// whatever its id.
#[test]
fn the_safe_list_rule_check_in_every_case() {
    let h = with_safe_list("");
    let check = |rules: Vec<Rule>| {
        h.fake.lock().unwrap().rules = rules;
        let checked = h.router().check().unwrap();
        assert_eq!(
            checked.found.split(" with ").next(),
            Some(
                if h.fake
                    .lock()
                    .unwrap()
                    .rules
                    .iter()
                    .any(|r| r.table == "raw" && r.list == "cctv_ban" && !r.disabled)
                {
                    "1 enabled rule(s) in /ip/firewall/raw"
                } else {
                    "1 enabled rule(s) in /ip/firewall/filter"
                }
            )
        );
        checked.safe_rule.unwrap()
    };
    let drop_raw = || Rule::new("raw", "cctv_ban", false);
    let drop_filter = || Rule::new("filter", "cctv_ban", false);
    let accept = |t| Rule::accept(t, "cctv_safe");
    let ok_raw = Ok(
        "1 enabled accept rule(s) in /ip/firewall/raw with src-address-list=cctv_safe \
                     before the drop rule for cctv_ban"
            .to_string(),
    );
    let counts = |table: &str, what: &str, fix: &str| {
        Err(format!(
            "no rule in /ip/firewall/{} with src-address-list=cctv_safe counts ({}): {}",
            table, what, fix
        ))
    };
    let missing = |table: &str| {
        Err(format!(
            "no rule in /ip/firewall/{} has src-address-list=cctv_safe: add one with \
             action=accept above the drop rule for cctv_ban, in the same table",
            table
        ))
    };
    // before the drop rule
    assert_eq!(check(vec![accept("raw"), drop_raw()]), ok_raw);
    // missing
    assert_eq!(check(vec![drop_raw()]), missing("raw"));
    // disabled
    let disabled = Rule {
        disabled: true,
        ..accept("raw")
    };
    assert_eq!(
        check(vec![disabled, drop_raw()]),
        counts("raw", "1 disabled", "enable it")
    );
    // invalid
    let invalid = Rule {
        invalid: true,
        ..accept("raw")
    };
    assert_eq!(
        check(vec![invalid, drop_raw()]),
        counts("raw", "1 invalid", "make it valid")
    );
    // another action
    assert_eq!(
        check(vec![Rule::new("raw", "cctv_safe", false), drop_raw()]),
        counts("raw", "1 with another action", "set action=accept")
    );
    // after the drop rule
    assert_eq!(
        check(vec![drop_raw(), accept("raw")]),
        counts(
            "raw",
            "1 after the drop rule",
            "move it above the drop rule"
        )
    );
    // in the other table
    assert_eq!(check(vec![accept("filter"), drop_raw()]), missing("raw"));
    assert_eq!(check(vec![accept("raw"), drop_filter()]), missing("filter"));
    // in filter, where the drop rule is
    assert_eq!(
        check(vec![accept("filter"), drop_filter()]),
        Ok("1 enabled accept rule(s) in /ip/firewall/filter with \
            src-address-list=cctv_safe before the drop rule for cctv_ban"
            .to_string())
    );
    // the order counts, not the ids: RouterOS keeps the id of a moved rule
    assert_eq!(
        check(vec![accept("raw").with_id(0x20), drop_raw().with_id(0x3)]),
        ok_raw
    );
    assert_eq!(
        check(vec![drop_raw().with_id(0x20), accept("raw").with_id(0x3)]),
        counts(
            "raw",
            "1 after the drop rule",
            "move it above the drop rule"
        )
    );
    // before the first usable drop rule, a disabled one before it does not
    // count
    let off = Rule::new("raw", "cctv_ban", true);
    assert_eq!(check(vec![off, accept("raw"), drop_raw()]), ok_raw);
    // one good rule is enough, the others are not named
    let disabled = Rule {
        disabled: true,
        ..accept("raw")
    };
    assert_eq!(check(vec![disabled, accept("raw"), drop_raw()]), ok_raw);
    // several reasons
    let disabled = Rule {
        disabled: true,
        ..accept("raw")
    };
    assert_eq!(
        check(vec![disabled, drop_raw(), accept("raw")]),
        counts(
            "raw",
            "1 disabled, 1 after the drop rule",
            "enable it, move it above the drop rule"
        )
    );
    // with the rule check off, the rule is not looked at
    let h = Harness::build(Opts {
        mikrotik_extra: "safe_list = cctv_safe\ncheck_rule = false",
        ..Default::default()
    });
    assert_eq!(h.router().check().unwrap().safe_rule, None);
    assert_eq!(h.fake.lock().unwrap().rule_queries.len(), 0);
    // and without a safe list, neither
    let h = Harness::build(Opts::default());
    assert_eq!(h.router().check().unwrap().safe_rule, None);
    assert_eq!(h.fake.lock().unwrap().rule_queries.len(), 1);
}

/// A dry run writes nothing to the safe list and says once what it would
/// do; the rule is still checked.
#[test]
fn a_dry_run_writes_nothing_to_the_safe_list() {
    let mut h = with_safe_list("dry_run = true");
    util::capture_log();
    assert!(h.engine.startup_check(h.host as u64));
    run(&mut h, 40, 30);
    h.restart();
    assert!(h.engine.startup_check(h.host as u64));
    let log = util::captured_log();
    assert_eq!(
        exactly(
            &log,
            "INFO DRY RUN: would keep 192.0.2.200 in the safe list cctv_safe for 00:30:00, \
             renewed at every firewall check"
        ),
        2,
        "once per start: {:?}",
        log
    );
    assert_eq!(
        starting(&log, "INFO safe list check ok: "),
        2,
        "at the starts; the periodic ones are DEBUG"
    );
    let f = h.fake.lock().unwrap();
    assert!(f.safe_log.is_empty() && f.listed.is_empty());
    assert!(!f.rest_log.iter().any(|r| r.contains("cctv_safe&address")
        || r.starts_with("PUT")
        || r.starts_with("PATCH")));
}

/// `--check` prints one line for the safe list, after the firewall's, and
/// changes nothing on the router.
#[test]
fn check_prints_the_safe_list() {
    use hik_f2b::health::Status;
    let mut h = with_safe_list("");
    let line = |h: &Harness| {
        h.check()
            .into_iter()
            .find(|l| l.item == "safe list")
            .unwrap()
    };
    let items: Vec<String> = h.check().into_iter().map(|l| l.item).collect();
    assert_eq!(
        items,
        [
            "nvr nvr1",
            "nvr nvr1 log",
            "firewall",
            "safe list",
            "own addresses",
            "telegram",
            "country database"
        ]
    );
    let rule = "1 enabled accept rule(s) in /ip/firewall/raw with src-address-list=cctv_safe \
                before the drop rule for cctv_ban";
    assert_eq!(
        line(&h).to_string(),
        format!(
            "ok       safe list: {}; 192.0.2.200 is not in cctv_safe (the service writes it at \
             every firewall check)",
            rule
        )
    );
    assert!(safe_writes(&h).is_empty());
    assert!(h.engine.startup_check(h.host as u64));
    // what the service wrote; --check writes nothing from here on
    assert_eq!(safe_writes(&h), vec![safe("added")]);
    requests(&h);
    assert_eq!(
        line(&h).to_string(),
        format!("ok       safe list: {}; 192.0.2.200 is in cctv_safe", rule)
    );
    h.fake.lock().unwrap().listed[0].timeout = None;
    assert_eq!(
        line(&h).to_string(),
        format!(
            "ok       safe list: {}; 192.0.2.200 is in cctv_safe without a timeout",
            rule
        )
    );
    // the rule is missing
    h.fake.lock().unwrap().rules = vec![Rule::new("raw", "cctv_ban", false)];
    let l = line(&h);
    assert_eq!(l.status, Status::Failed);
    assert_eq!(
        l.to_string(),
        "FAILED   safe list: no rule in /ip/firewall/raw has src-address-list=cctv_safe: add one \
         with action=accept above the drop rule for cctv_ban, in the same table; 192.0.2.200 is \
         in cctv_safe without a timeout"
    );
    // no drop rule: the rule cannot be placed
    h.fake.lock().unwrap().rules = vec![];
    assert_eq!(
        line(&h).to_string(),
        "FAILED   safe list: not checked: the firewall check failed; 192.0.2.200 is in cctv_safe \
         without a timeout"
    );
    // the router cannot be used
    h.fake.lock().unwrap().router_unreachable = true;
    assert_eq!(
        line(&h).to_string(),
        "FAILED   safe list: not checked: the firewall check failed"
    );
    h.fake.lock().unwrap().router_unreachable = false;
    // the address toward the router is not known (loopback)
    h.own.set_local(Ok(std::net::Ipv4Addr::LOCALHOST));
    h.fake.lock().unwrap().rules = vec![
        Rule::accept("raw", "cctv_safe"),
        Rule::new("raw", "cctv_ban", false),
    ];
    assert_eq!(
        line(&h).to_string(),
        format!(
            "ok       safe list: {}; the own address toward the router is not known",
            rule
        )
    );
    // with the rule check off
    h.ini = h.ini.replace(
        "safe_list = cctv_safe",
        "safe_list = cctv_safe\ncheck_rule = false",
    );
    h.own.set_local(Ok(ip(OWN)));
    assert_eq!(
        line(&h).to_string(),
        "ok       safe list: rule check is off; 192.0.2.200 is in cctv_safe without a timeout"
    );
    // nothing was written by any of these
    assert!(safe_writes(&h).is_empty());
    assert!(!requests(&h)
        .iter()
        .any(|r| r.starts_with("PUT") || r.starts_with("PATCH") || r.starts_with("DELETE")));
    // the command itself prints the line in its place
    let (_, stdout, _) = hik_f2b(&h, &h.ini, &["--check"]);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines[2].starts_with("ok       firewall: ") && lines[4].starts_with("ok       own "),
        "{}",
        stdout
    );
    // the operating system reaches the fakes from loopback
    assert_eq!(
        lines[3],
        "ok       safe list: rule check is off; the own address toward the router is not known"
    );
}

// ------------------------------------------------------------------ --check

#[test]
fn check_command_reports_each_item_and_changes_nothing() {
    use hik_f2b::health::Status;
    let h = Harness::with(Opts {
        telegram: true,
        second_nvr: true,
        ..Default::default()
    });
    let slow = h.fake2.clone().unwrap();
    slow.lock().unwrap().nvr_auth_ok = false;
    h.burst("10:01", ATTACKER, 5); // not read by --check
    let saved = h.engine.state().serialize();

    let lines = h.check();
    let summary: Vec<(String, Status)> = lines
        .iter()
        .map(|l| (l.item.clone(), l.status.clone()))
        .collect();
    // an NVR that cannot be read has no line about its log
    assert_eq!(
        summary,
        vec![
            ("nvr nvr1".to_string(), Status::Ok),
            ("nvr nvr1 log".to_string(), Status::Ok),
            ("nvr nvr2".to_string(), Status::Failed),
            ("firewall".to_string(), Status::Ok),
            ("own addresses".to_string(), Status::Ok),
            ("telegram".to_string(), Status::Ok),
            ("country database".to_string(), Status::Off),
        ]
    );
    assert_eq!(
        lines[0].to_string(),
        "ok       nvr nvr1: login accepted, device time 2026-01-10T10:00:00Z (2:00:00 ahead of \
         the host clock), log search works"
    );
    // the burst is after the device time: nothing in the window
    assert_eq!(
        lines[1].to_string(),
        "ok       nvr nvr1 log: order not known, page size not known (0 entries read from the \
         last 24 h)"
    );
    assert_eq!(
        lines[2].to_string(),
        "FAILED   nvr nvr2: login rejected (HTTP 401)"
    );
    assert_eq!(
        lines[3].detail,
        "1 enabled rule(s) in /ip/firewall/raw with src-address-list=cctv_ban"
    );

    h.fake.lock().unwrap().rules.clear();
    let lines = h.check();
    assert_eq!(lines[3].status, Status::Failed);

    // nothing banned, sent or remembered
    assert_eq!(h.engine.state().serialize(), saved);
    assert!(h.banned().is_empty());
    assert_eq!(h.fake.lock().unwrap().tg_attempts, 0);
    assert!(h.engine.alerted_problems().is_empty());
    assert_eq!(
        h.engine.readers()[1].retry_after(),
        0,
        "no backoff from --check"
    );

    let h = Harness::with(Opts {
        mikrotik: false,
        ..Default::default()
    });
    let lines = h.check();
    assert_eq!(lines[2].item, "firewall");
    assert_eq!(lines[2].status, Status::Off);
    // the own addresses are found in notify-only mode too
    assert_eq!(lines[3].item, "own addresses");
    assert_eq!(lines[3].status, Status::Ok);
    assert_eq!(lines[4].status, Status::Off);
    assert_eq!(h.fake.lock().unwrap().router_requests, 0);
}

#[test]
fn dump_fails_when_an_nvr_cannot_be_read() {
    let h = Harness::build(Opts {
        second_nvr: true,
        ..Default::default()
    });
    h.add("09:30:00", ATTACKER);
    h.fake2.as_ref().unwrap().lock().unwrap().nvr_down = true;
    let ini = h.dir.join("hik-f2b.ini");
    std::fs::write(&ini, &h.ini).unwrap();
    let run = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_hik-f2b"))
            .arg("--config")
            .arg(&ini)
            .args(args)
            .output()
            .unwrap()
    };
    let out = run(&["--dump", "--hours", "2"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{}\n{}", stdout, stderr);
    // what could be read is still printed, the error goes to stderr
    assert!(stdout.contains("=== nvr1"), "{}", stdout);
    assert!(stdout.contains("MATCH"), "{}", stdout);
    assert!(!stdout.contains("ERROR"), "{}", stdout);
    assert!(stderr.contains("ERROR: nvr2: "), "{}", stderr);
    assert!(
        stderr.contains("hik-f2b: 1 of 2 NVR(s) could not be read"),
        "{}",
        stderr
    );
    h.fake2.as_ref().unwrap().lock().unwrap().nvr_down = false;
    let out = run(&["--dump", "--hours", "2"]);
    assert_eq!(out.status.code(), Some(0));
    // options that exclude each other
    let out = run(&["--check", "--dump"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--check and --dump cannot be used together")
    );
}

/// The log line of `--check` for one NVR, after a few entries.
fn check_log_line(newest_first: bool, entries: &[&str]) -> (String, u32) {
    let h = Harness::raw(false);
    h.fake.lock().unwrap().newest_first = newest_first;
    for clock in entries {
        h.add(clock, ATTACKER);
    }
    let lines = h.check();
    assert_eq!(lines[1].item, "nvr nvr1 log");
    let searches = h.fake.lock().unwrap().search_requests;
    (lines[1].to_string(), searches)
}

/// `--check` tells the order of a log search from the entries it gets.
#[test]
fn check_shows_the_order_of_the_log() {
    let entries = ["09:10:00", "09:20:00", "09:30:00"];
    for (newest_first, order) in [(false, "oldest first"), (true, "newest first")] {
        let (line, _) = check_log_line(newest_first, &entries);
        assert_eq!(
            line,
            format!(
                "ok       nvr nvr1 log: {}, page size not known (3 entries read from the last \
                 24 h)",
                order
            )
        );
    }
}

/// With fewer than two entries with different times, the order is not
/// known; it is not a failure.
#[test]
fn check_with_too_few_entries_does_not_guess_the_order() {
    for entries in [&[][..], &["09:10:00"], &["09:10:00", "09:10:00"]] {
        let (line, _) = check_log_line(false, entries);
        assert_eq!(
            line,
            format!(
                "ok       nvr nvr1 log: order not known, page size not known ({} entries read \
                 from the last 24 h)",
                entries.len()
            )
        );
    }
    // entries older than a day are not looked at
    let h = Harness::raw(false);
    Harness::add_at(&h.fake, "2026-01-09T09:00:00", ATTACKER);
    Harness::add_at(&h.fake, "2026-01-09T09:30:00", ATTACKER);
    let lines = h.check();
    assert!(
        lines[1].detail.starts_with("order not known"),
        "{}",
        lines[1]
    );
}

/// A window with more entries than one page tells the page size the NVR
/// returns (the fake, as the tested NVRs, gives 64 whatever is asked), and
/// the search stops after two pages however busy the log is.
#[test]
fn check_shows_the_page_size_and_reads_two_pages_at_most() {
    let clocks: Vec<String> = (0..1000)
        .map(|i| format!("09:{:02}:{:02}", 10 + i / 60 % 50, i % 60))
        .collect();
    let entries: Vec<&str> = clocks.iter().map(String::as_str).collect();
    for (newest_first, order) in [(false, "oldest first"), (true, "newest first")] {
        let (line, searches) = check_log_line(newest_first, &entries);
        assert_eq!(
            line,
            format!("ok       nvr nvr1 log: {}, 64 entries per page", order)
        );
        assert_eq!(searches, 2);
    }
    // all in one second: the page size is known, the order is not
    let same = vec!["09:10:00"; 70];
    let (line, searches) = check_log_line(false, &same);
    assert_eq!(
        line,
        "ok       nvr nvr1 log: order not known, 64 entries per page (70 entries read from the \
         last 24 h)"
    );
    assert_eq!(searches, 2);
}

/// The clock difference is reported, whatever its size.
#[test]
fn check_shows_the_clock_difference() {
    for (skew, shown) in [
        (SKEW, "2:00:00 ahead of the host clock"),
        (0, "same as the host clock"),
        (-3 * 3600 - 7, "3:00:07 behind the host clock"),
    ] {
        let mut h = Harness::raw(false);
        h.fake.lock().unwrap().skew = skew;
        let host = h.host;
        h.set_host(host);
        let lines = h.check();
        assert_eq!(lines[0].status, hik_f2b::health::Status::Ok);
        assert!(
            lines[0].detail.contains(&format!("({})", shown)),
            "{}",
            lines[0]
        );
    }
}

// ------------------------------------------------------------- country_db

const FLAG_MD: &str = "\u{1f1f2}\u{1f1e9}";

/// Writes a synthetic country database (198.51.100.0/24 = MD) into the
/// harness directory and restarts the engine with `country_db` set to it.
fn with_country_db(h: &mut Harness) -> PathBuf {
    let path = h.dir.join("country.mmdb");
    std::fs::write(&path, mmdb::simple(28, 6, "MD")).unwrap();
    with_setting(h, &format!("country_db = {}", path.display()));
    path
}

/// Adds `line` to the `[general]` section of the config and restarts the
/// engine with it, as an operator does.
fn with_setting(h: &mut Harness, line: &str) {
    let general = "[general]
";
    assert!(h.ini.starts_with(general));
    h.ini.insert_str(
        general.len(),
        &format!(
            "{}
",
            line
        ),
    );
    h.restart();
}

#[test]
fn country_shows_in_comment_log_and_telegram() {
    let mut h = Harness::new(true);
    with_country_db(&mut h);
    util::capture_log();
    h.engine.startup_country();
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert_eq!(h.banned(), vec![ATTACKER]);
    let body = h.fake.lock().unwrap().ban_bodies[0].clone();
    assert!(
        body.contains("\"comment\":\"hik-f2b nvr1 user=admin 2026-01-10T08:01:14Z country=MD\""),
        "{}",
        body
    );
    assert!(!body.contains(FLAG_MD), "{}", body);
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 1);
    assert_eq!(
        texts[0].lines().next().unwrap(),
        format!(
            "\u{26d4} hik-f2b: 198.51.100.7 ({} MD) banned for 1d00:00:00",
            FLAG_MD
        )
    );
    let log = util::captured_log();
    assert_eq!(
        logged(
            &log,
            "INFO country database: Test-Country, built 2026-11-01"
        ),
        1,
        "{:?}",
        log
    );
    assert_eq!(
        logged(
            &log,
            "WARNING BAN 198.51.100.7 [MD] for 1d00:00:00 (hik-f2b nvr1 user=admin \
             2026-01-10T08:01:14Z country=MD)"
        ),
        1,
        "{:?}",
        log
    );
    assert_eq!(logged(&log, FLAG_MD), 0, "no flag in the log");
    assert_eq!(logged(&log, "country lookup"), 0, "{:?}", log);

    // an address the database does not know: no country anywhere
    h.burst("10:10", "203.0.113.50", 5);
    h.cycle("10:11:00");
    let body = h.fake.lock().unwrap().ban_bodies[1].clone();
    assert!(
        body.ends_with("\"comment\":\"hik-f2b nvr1 user=admin 2026-01-10T08:10:14Z\"}"),
        "{}",
        body
    );
    assert_eq!(
        telegram_texts(&h)[1].lines().next().unwrap(),
        "\u{26d4} hik-f2b: 203.0.113.50 banned for 1d00:00:00"
    );
    assert_eq!(
        logged(&util::captured_log(), "WARNING BAN 203.0.113.50 for"),
        1
    );
}

#[test]
fn country_in_dry_run_and_notify_only_lines() {
    let mut h = Harness::new(false);
    with_country_db(&mut h);
    with_setting(&mut h, "dry_run = true");
    util::capture_log();
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert!(h.banned().is_empty());
    let log = util::captured_log();
    assert_eq!(
        logged(
            &log,
            "WARNING DRY RUN: would ban 198.51.100.7 [MD] for 1d00:00:00 ("
        ),
        1,
        "{:?}",
        log
    );

    let mut h = Harness::with(Opts {
        mikrotik: false,
        ..Default::default()
    });
    with_country_db(&mut h);
    util::capture_log();
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    let log = util::captured_log();
    assert_eq!(
        logged(
            &log,
            "WARNING DETECTED 198.51.100.7 [MD] (no firewall configured, not banned) ("
        ),
        1,
        "{:?}",
        log
    );
}

#[test]
fn missing_country_db_never_holds_up_a_ban() {
    let mut h = Harness::new(true);
    let path = h.dir.join("missing.mmdb");
    with_setting(&mut h, &format!("country_db = {}", path.display()));
    util::capture_log();
    h.engine.startup_country();
    let log = util::captured_log();
    assert_eq!(
        logged(
            &log,
            "WARNING country database cannot be read, bans go on without a country: cannot read "
        ),
        1,
        "{:?}",
        log
    );

    // The router is down for three cycles: the same lookup failure is not
    // logged again on every retry.
    h.fake.lock().unwrap().router_down = true;
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    h.cycle("10:02:30");
    h.cycle("10:03:00");
    assert_eq!(h.engine.state().ledger.waiting(), 1);
    h.fake.lock().unwrap().router_down = false;
    h.cycle("10:03:30");
    assert_eq!(h.banned(), vec![ATTACKER]);
    let body = h.fake.lock().unwrap().ban_bodies[0].clone();
    assert!(
        body.ends_with("\"comment\":\"hik-f2b nvr1 user=admin 2026-01-10T08:01:14Z\"}"),
        "{}",
        body
    );
    assert_eq!(
        telegram_texts(&h)[0].lines().next().unwrap(),
        "\u{26d4} hik-f2b: 198.51.100.7 banned for 1d00:00:00"
    );
    let log = util::captured_log();
    assert_eq!(logged(&log, "country"), 0, "already reported: {:?}", log);
    assert_eq!(logged(&log, "WARNING BAN 198.51.100.7 for 1d00:00:00"), 1);

    // a broken file is a new reason: logged once
    std::fs::write(&path, b"not a database").unwrap();
    h.burst("10:10", "198.51.100.8", 5);
    h.cycle("10:11:00");
    assert_eq!(h.banned().len(), 2);
    let log = util::captured_log();
    assert_eq!(
        logged(
            &log,
            "WARNING country lookup failed, bans go on without a country: not a MaxMind DB"
        ),
        1,
        "{:?}",
        log
    );

    // the file is replaced by a good one, without a restart
    std::fs::write(&path, mmdb::simple(24, 4, "MD")).unwrap();
    h.burst("10:20", "198.51.100.9", 5);
    h.cycle("10:21:00");
    let log = util::captured_log();
    assert_eq!(
        logged(&log, "INFO country lookups work again"),
        1,
        "{:?}",
        log
    );
    assert_eq!(
        logged(&log, "WARNING BAN 198.51.100.9 [MD] for"),
        1,
        "{:?}",
        log
    );
    h.burst("10:30", "198.51.100.10", 5);
    h.cycle("10:31:00");
    assert_eq!(logged(&util::captured_log(), "work again"), 0);
}

#[test]
fn without_country_db_nothing_changes() {
    let mut h = Harness::new(true);
    assert!(h.config().country_db.is_none());
    util::capture_log();
    h.engine.startup_country();
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    let body = h.fake.lock().unwrap().ban_bodies[0].clone();
    assert_eq!(
        body,
        "{\"list\":\"cctv_ban\",\"address\":\"198.51.100.7\",\"timeout\":\"1d00:00:00\",\
         \"comment\":\"hik-f2b nvr1 user=admin 2026-01-10T08:01:14Z\"}"
    );
    assert_eq!(
        telegram_texts(&h),
        vec![
            "\u{26d4} hik-f2b: 198.51.100.7 banned for 1d00:00:00\nNVR: nvr1\n\
              User tried: admin\nFailed logins: 5 within 3600 s"
        ]
    );
    let log = util::captured_log();
    assert_eq!(logged(&log, "country"), 0, "{:?}", log);
    assert_eq!(
        logged(
            &log,
            "WARNING BAN 198.51.100.7 for 1d00:00:00 (hik-f2b nvr1 user=admin 2026-01-10T08:01:14Z)"
        ),
        1,
        "{:?}",
        log
    );
}

#[test]
fn check_reports_the_country_database() {
    use hik_f2b::health::Status;
    let mut h = Harness::new(false);
    let line = |h: &mut Harness| h.check().pop().unwrap();
    let off = line(&mut h);
    assert_eq!(off.to_string(), "off      country database: not configured");
    let path = with_country_db(&mut h);
    let ok = line(&mut h);
    assert_eq!(ok.status, Status::Ok);
    assert_eq!(
        ok.to_string(),
        "ok       country database: Test-Country, built 2026-11-01"
    );
    std::fs::write(&path, &mmdb::simple(24, 6, "MD")[..200]).unwrap();
    let failed = line(&mut h);
    assert_eq!(failed.status, Status::Failed);
    assert!(failed.detail.contains("no metadata marker"), "{}", failed);
    std::fs::remove_file(&path).unwrap();
    let failed = line(&mut h);
    assert_eq!(failed.status, Status::Failed);
    assert!(failed.detail.starts_with("cannot read "), "{}", failed);
    assert_eq!(h.fake.lock().unwrap().tg_attempts, 0);
}

// ------------------------------------------------------ one-shot commands

/// Runs hik-f2b with `ini` as its config and `args`: the exit code, stdout
/// and stderr.
fn hik_f2b(h: &Harness, ini: &str, args: &[&str]) -> (Option<i32>, String, String) {
    let path = h.dir.join("one-shot.ini");
    std::fs::write(&path, ini).unwrap();
    // Not readable by others, or a warning about the inline secrets would
    // come first.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_hik-f2b"))
        .arg("--config")
        .arg(&path)
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The URL of `nvr` in the harness's config.
fn nvr_url(h: &Harness, nvr: &str) -> String {
    let section = format!("[nvr:{}]\nurl = ", nvr);
    let at = h.ini.find(&section).unwrap() + section.len();
    h.ini[at..].lines().next().unwrap().to_string()
}

/// What `--dump` prints, exactly: entries that match `log_filter` and
/// others, and an NVR that cannot be read, on stderr.
#[test]
fn dump_prints_the_log_of_each_nvr() {
    let h = Harness::build(Opts {
        second_nvr: true,
        ..Default::default()
    });
    h.add("09:30:00", ATTACKER);
    h.add_full("09:40:00", OWNER, "operator", "remoteLogin");
    h.fake2.as_ref().unwrap().lock().unwrap().nvr_auth_ok = false;
    let out = hik_f2b(&h, &h.ini, &["--dump", "--hours", "2"]);
    assert_eq!(
        out,
        (
            Some(1),
            format!(
                "=== nvr1 ({})\n\
                 device time: 2026-01-10T10:00:00Z\n\
                 2 entries with metaId log.std-cgi.com/Exception in the last 2 h\n\
                 MATCH  2026-01-10T09:30:00Z  ip=198.51.100.7    user=\"admin\"            \
                 log.hikvision.com/Exception/illlegealAccess\n\
                 \x20      2026-01-10T09:40:00Z  ip=203.0.113.20    user=\"operator\"         \
                 log.hikvision.com/Exception/remoteLogin\n\
                 === nvr2 ({})\n",
                nvr_url(&h, "nvr1"),
                nvr_url(&h, "nvr2")
            ),
            "ERROR: nvr2: HTTP 401\nhik-f2b: 1 of 2 NVR(s) could not be read\n".to_string()
        )
    );
    // nothing is banned
    assert_eq!(h.fake.lock().unwrap().router_requests, 0);

    // with the raw XML of each page
    let h = Harness::build(Opts {
        mikrotik: false,
        ..Default::default()
    });
    h.add("09:30:00", ATTACKER);
    let out = hik_f2b(&h, &h.ini, &["--dump", "--raw", "--hours", "1"]);
    let xml = [
        "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>",
        "<CMSearchResult version=\"1.0\" xmlns=\"http://www.hikvision.com/ver20/XMLSchema\">",
        "<searchID>{x}</searchID>",
        "<responseStatus>true</responseStatus>",
        "<responseStatusStrg>OK</responseStatusStrg>",
        "<numOfMatches>1</numOfMatches>",
        "<matchList>",
        "<searchMatchItem>",
        "<logDescriptor>",
        "<metaId>log.hikvision.com/Exception/illlegealAccess</metaId>",
        "<StartDateTime>2026-01-10T09:30:00Z</StartDateTime>",
        "<paraType></paraType>",
        "<userName>admin</userName>",
        "<ipAddress>198.51.100.7</ipAddress>",
        "</logDescriptor>",
        "</searchMatchItem>",
        "</matchList>",
        "</CMSearchResult>",
        "",
    ]
    .join("\n");
    assert_eq!(
        out,
        (
            Some(0),
            format!(
                "=== nvr1 ({})\n\
                 device time: 2026-01-10T10:00:00Z\n\
                 {}\n\
                 1 entries with metaId log.std-cgi.com/Exception in the last 1 h\n\
                 MATCH  2026-01-10T09:30:00Z  ip=198.51.100.7    user=\"admin\"            \
                 log.hikvision.com/Exception/illlegealAccess\n",
                nvr_url(&h, "nvr1"),
                xml
            ),
            String::new()
        )
    );
}

/// What `--check` prints, exactly, and its exit status. The device clock
/// is set to the real host clock here, as the binary compares the two.
#[test]
fn check_prints_one_line_per_item() {
    let mut h = Harness::build(Opts {
        telegram: true,
        second_nvr: true,
        ..Default::default()
    });
    h.fake2.as_ref().unwrap().lock().unwrap().nvr_auth_ok = false;
    let start = util::unix_now() as i64;
    h.set_host(start);
    Harness::add_at(&h.fake, &device(start + SKEW - 600), ATTACKER);
    Harness::add_at(&h.fake, &device(start + SKEW - 300), ATTACKER);
    let (code, stdout, stderr) = hik_f2b(&h, &h.ini, &["--check"]);
    let end = util::unix_now() as i64;
    assert_eq!(
        (code, stderr.as_str()),
        (Some(1), "hik-f2b: 1 check(s) failed\n")
    );
    // the host clock may have moved on by a second or two
    let expected = |host: i64| {
        let ahead = start + SKEW - host;
        format!(
            "ok       nvr nvr1: login accepted, device time {} ({}:{:02}:{:02} ahead of the host \
             clock), log search works\n\
             ok       nvr nvr1 log: oldest first, page size not known (2 entries read from the \
             last 24 h)\n\
             FAILED   nvr nvr2: login rejected (HTTP 401)\n\
             ok       firewall: 1 enabled rule(s) in /ip/firewall/raw with \
             src-address-list=cctv_ban\n\
             ok       own addresses: router 127.0.0.1 from 127.0.0.1, nvr1 127.0.0.1 from \
             127.0.0.1, nvr2 127.0.0.1 from 127.0.0.1 (never banned)\n\
             ok       telegram: configured, health alerts on; nothing sent (see --test-notify)\n\
             off      country database: not configured\n",
            util::fmt_ts(start + SKEW),
            ahead / 3600,
            ahead / 60 % 60,
            ahead % 60
        )
    };
    assert!(
        (start..=end).any(|host| stdout == expected(host)),
        "{}\n{}",
        stdout,
        expected(start)
    );
    // nothing banned or sent
    assert!(h.banned().is_empty());
    assert_eq!(h.fake.lock().unwrap().tg_attempts, 0);

    // all well: exit status 0
    let h = Harness::build(Opts {
        mikrotik: false,
        ..Default::default()
    });
    let (code, stdout, stderr) = hik_f2b(&h, &h.ini, &["--check"]);
    assert_eq!((code, stderr.as_str()), (Some(0), ""));
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 6, "{}", stdout);
    assert!(
        lines[0]
            .starts_with("ok       nvr nvr1: login accepted, device time 2026-01-10T10:00:00Z ("),
        "{}",
        lines[0]
    );
    assert!(
        lines[0].ends_with(" behind the host clock), log search works"),
        "{}",
        lines[0]
    );
    assert_eq!(
        lines[1..],
        [
            "ok       nvr nvr1 log: order not known, page size not known (0 entries read from \
             the last 24 h)",
            "off      firewall: not configured (notify-only mode)",
            "ok       own addresses: nvr1 127.0.0.1 from 127.0.0.1 (never banned)",
            "off      telegram: not configured",
            "off      country database: not configured",
        ]
    );
}

/// What `--test-ban` prints and asks of the router, exactly.
#[test]
fn test_ban_prints_what_the_router_did() {
    let h = Harness::build(Opts::default());
    assert_eq!(
        hik_f2b(&h, &h.ini, &["--test-ban", "192.0.2.1"]),
        (
            Some(0),
            "ok: 192.0.2.1 added to MikroTik address-list cctv_ban (60 s)\n".to_string(),
            String::new()
        )
    );
    assert_eq!(h.banned(), vec!["192.0.2.1"]);
    assert_eq!(
        h.fake.lock().unwrap().ban_bodies,
        vec![
            "{\"list\":\"cctv_ban\",\"address\":\"192.0.2.1\",\"timeout\":\"00:01:00\",\
             \"comment\":\"hik-f2b test\"}"
        ]
    );
    assert_eq!(
        hik_f2b(&h, &h.ini, &["--test-ban", "192.0.2.1"]),
        (
            Some(0),
            "ok: 192.0.2.1 is already in MikroTik address-list cctv_ban (60 s)\n".to_string(),
            String::new()
        )
    );
    h.fake.lock().unwrap().router_down = true;
    assert_eq!(
        hik_f2b(&h, &h.ini, &["--test-ban", "192.0.2.2"]),
        (
            Some(1),
            String::new(),
            "hik-f2b: the firewall answers with an error: HTTP 500: \
             {\"error\":500,\"message\":\"down\"}\n"
                .to_string()
        )
    );
    let h = Harness::build(Opts {
        mikrotik: false,
        ..Default::default()
    });
    assert_eq!(
        hik_f2b(&h, &h.ini, &["--test-ban", "192.0.2.1"]),
        (
            Some(1),
            String::new(),
            "hik-f2b: --test-ban needs a firewall, but there is no [mikrotik] section in the \
             config\n"
                .to_string()
        )
    );
}

/// `--test-ban` refuses an own address, as the service never bans one: it
/// says why, exits non-zero and sends nothing to the router. The command
/// asks the operating system, which reaches the fakes from loopback.
#[test]
fn test_ban_refuses_an_own_address() {
    let h = Harness::build(Opts::default());
    assert_eq!(
        hik_f2b(&h, &h.ini, &["--test-ban", "127.0.0.1"]),
        (
            Some(1),
            String::new(),
            "hik-f2b: --test-ban 127.0.0.1: that is an own address of hik-f2b (router 127.0.0.1 \
             from 127.0.0.1, nvr1 127.0.0.1 from 127.0.0.1), and hik-f2b never bans its own \
             addresses; nothing was sent to the router\n"
                .to_string()
        )
    );
    let f = h.fake.lock().unwrap();
    assert_eq!(f.rest_requests, 0);
    assert!(f.bans.is_empty() && f.put_log.is_empty());
}

/// What `--test-notify` prints and sends, exactly.
#[test]
fn test_notify_prints_whether_the_message_was_sent() {
    let h = Harness::build(Opts {
        telegram: true,
        ..Default::default()
    });
    assert_eq!(
        hik_f2b(&h, &h.ini, &["--test-notify"]),
        (
            Some(0),
            "ok: test message sent\n".to_string(),
            String::new()
        )
    );
    assert_eq!(
        h.fake.lock().unwrap().tg_sent,
        vec![
            "chat_id=-1001234567890&text=hik-f2b+test+message%3A+notifications+work.&\
             message_thread_id=42"
        ]
    );
    h.fake.lock().unwrap().tg_fail = true;
    assert_eq!(
        hik_f2b(&h, &h.ini, &["--test-notify"]),
        (
            Some(1),
            String::new(),
            "hik-f2b: HTTP 500: {\"ok\":false,\"description\":\"boom at /bot<token>/x\"}\n"
                .to_string()
        )
    );
    let h = Harness::build(Opts::default());
    assert_eq!(
        hik_f2b(&h, &h.ini, &["--test-notify"]),
        (
            Some(1),
            String::new(),
            "hik-f2b: no [telegram] section in the config\n".to_string()
        )
    );
}

/// Every command sets up the router, Telegram and NVR clients before it
/// does anything, in that order: a client that cannot be set up fails
/// every command the same way. The service logs its start first.
#[test]
fn every_command_sets_up_all_clients_first() {
    let h = Harness::build(Opts {
        telegram: true,
        ..Default::default()
    });
    let nvr_ca = h.dir.join("missing-ca.pem");
    let nvr_https = h.ini.replace(
        &format!("[nvr:nvr1]\nurl = http://127.0.0.1:{}", h.port),
        &format!(
            "[nvr:nvr1]\nurl = https://127.0.0.1:{}\nca_file = {}",
            h.port,
            nvr_ca.display()
        ),
    );
    assert_ne!(nvr_https, h.ini);
    let router_ca = h.dir.join("router-ca.pem");
    let both_https = nvr_https.replace(
        &format!("[mikrotik]\nurl = http://127.0.0.1:{}", h.port),
        &format!(
            "[mikrotik]\nurl = https://127.0.0.1:{}\nca_file = {}",
            h.port,
            router_ca.display()
        ),
    );
    assert_ne!(both_https, nvr_https);
    let nvr_error = format!(
        "hik-f2b: nvr nvr1: cannot read CA file {}: entity not found\n",
        nvr_ca.display()
    );
    let router_error = format!(
        "hik-f2b: mikrotik: cannot read CA file {}: entity not found\n",
        router_ca.display()
    );
    for args in [
        &["--check"][..],
        &["--dump"],
        &["--test-ban", "192.0.2.1"],
        &["--test-notify"],
    ] {
        assert_eq!(
            hik_f2b(&h, &nvr_https, args),
            (Some(1), String::new(), nvr_error.clone()),
            "{:?}",
            args
        );
        assert_eq!(
            hik_f2b(&h, &both_https, args),
            (Some(1), String::new(), router_error.clone()),
            "{:?}",
            args
        );
    }
    // the service: the start is logged, then the NVR client fails
    let without_time = |stdout: &str| -> Vec<String> {
        stdout
            .lines()
            .map(|line| line.split_once(' ').unwrap().1.to_string())
            .collect()
    };
    let no_state = format!(
        "INFO no state file at {} yet: starting with an empty state",
        h.dir.join("state").display()
    );
    let (code, stdout, stderr) = hik_f2b(&h, &nvr_https, &["--once"]);
    assert_eq!((code, stderr), (Some(1), nvr_error));
    assert_eq!(
        without_time(&stdout),
        [
            no_state.clone(),
            format!(
                "INFO hik-f2b {} started: 1 NVR(s), maxretry=5 findtime=3600s bantime=86400s \
                 telegram=on",
                env!("CARGO_PKG_VERSION")
            ),
            "INFO mode: ban on MikroTik, address-list cctv_ban".to_string(),
        ]
    );
    // ... and a router client that fails comes before the start
    let (code, stdout, stderr) = hik_f2b(&h, &both_https, &["--once"]);
    assert_eq!((code, stderr), (Some(1), router_error));
    assert_eq!(without_time(&stdout), [no_state]);
    let f = h.fake.lock().unwrap();
    assert_eq!(
        (f.isapi_requests, f.rest_requests, f.tg_attempts),
        (0, 0, 0)
    );
}
