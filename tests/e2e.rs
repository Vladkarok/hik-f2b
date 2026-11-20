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
use hik_f2b::state::State;
use hik_f2b::util;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

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
    assert!(h.engine.state.pending.is_empty());
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
    assert!(!h.engine.state.nvr.contains_key("nvr1"));
    assert_eq!(h.engine.nvrs[0].failed_polls, 0, "no window to skip yet");
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
    assert_eq!(h.engine.state.fails[&attacker()].len(), 4);

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
    assert!(h.engine.state.fails.is_empty());
    assert!(h.engine.state.pending.is_empty());
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
    assert!(h.engine.state.fails.is_empty());
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
    assert_eq!(h.engine.state.pending.len(), 1);
    h.fake.lock().unwrap().router_down = false;
    h.cycle("10:02:30");
    assert_eq!(h.banned(), vec![ATTACKER]);
    assert!(h.engine.state.pending.is_empty());
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
    assert!(h.engine.state.pending.contains_key(&ip(OWNER)));
    assert!(h.engine.state.pending.contains_key(&attacker()));
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
    assert!(!h.engine.state.pending.contains_key(&ip(OWNER)));
    assert_eq!(h.fails(OWNER), 0);
    assert_eq!(h.fails(NEIGHBOUR), 0);

    h.fake.lock().unwrap().router_unreachable = false;
    h.advance(30);
    assert_eq!(h.banned(), vec![ATTACKER], "no ban request for the owner");
    assert!(h.engine.state.pending.is_empty());
    assert!(h.fake.lock().unwrap().lookups.is_empty());
    let path = h.dir.join("state");
    h.engine.state.save(&path).unwrap();
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
    h.cycle("10:01:00");
    assert!(h.engine.nvrs[0].retry_after > 0);
    // exactly one refused login, so the NVR's own lock is not provoked
    assert_eq!(h.fake.lock().unwrap().refused_logins, 1);
    h.fake.lock().unwrap().nvr_auth_ok = true;
    let before = h.fake.lock().unwrap().search_requests;
    h.cycle("10:01:30"); // still backing off: the NVR is not contacted
    assert_eq!(h.fake.lock().unwrap().search_requests, before);
    assert_eq!(h.fake.lock().unwrap().refused_logins, 1);
    // after auth_backoff (900 s) it is contacted again
    h.cycle("10:16:30");
    assert!(h.fake.lock().unwrap().search_requests > before);
}

#[test]
fn host_clock_jumping_back_does_not_stall_the_backoff() {
    let mut h = Harness::new(false);
    h.fake.lock().unwrap().nvr_auth_ok = false;
    h.cycle("10:01:00");
    assert!(h.engine.nvrs[0].retry_after > 0);
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
    let mut h = Harness::new(true);
    h.engine.cfg.dry_run = true;
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert!(h.banned().is_empty());
    assert!(h.engine.state.banned.contains_key(&attacker()));
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

#[test]
fn ban_rate_limit_holds_back_a_flood() {
    let mut h = Harness::new(false);
    h.engine.cfg.max_bans_per_hour = 2;
    for ip in ["198.51.100.1", "198.51.100.2", "198.51.100.3"] {
        h.burst("10:01", ip, 5);
    }
    h.cycle("10:02:00");
    assert_eq!(h.banned().len(), 2);
    assert_eq!(h.engine.state.pending.len(), 1);
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

#[test]
fn telegram_errors_never_reveal_the_token() {
    let h = Harness::new(true);
    h.fake.lock().unwrap().tg_fail = true;
    let err = h.engine.notifier.as_ref().unwrap().send("x").unwrap_err();
    assert!(!err.contains(TOKEN), "{}", err);
    assert!(err.contains("<token>"), "{}", err);
}

#[test]
fn state_survives_a_restart() {
    let mut h = Harness::new(false);
    h.burst("10:01", ATTACKER, 4);
    h.cycle("10:02:00");
    let path = h.dir.join("state");
    h.engine.state.save(&path).unwrap();
    let restored = State::load(&path);
    assert_eq!(restored, h.engine.state);
    assert_eq!(restored.fails[&attacker()].len(), 4);
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
/// `lookback` is not a jump, but it moves the read cursor back to the new
/// device time, so the next window starts before the previous one: entries
/// in between are no longer in `seen` and are counted a second time.
#[test]
#[ignore = "a small backward device clock correction moves the read window back and counts \
            entries again"]
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
    h.advance(30);
    h.advance(30);
    assert_eq!(h.fails(OWNER), 2, "the typo at 10:01:00 was counted twice");
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
    // an unescaped & breaks the XML document itself
    Harness::entry_to(
        &fake,
        &at("22"),
        "198.51.100.52",
        b"a & b",
        "illlegealAccess",
    );
    h.cycle("10:02:00");
    assert_eq!(h.banned(), vec![ATTACKER]);
    assert_eq!(h.fails("198.51.100.50"), 1);
    assert_eq!(h.fails("198.51.100.51"), 1);
    assert_eq!(h.fails("198.51.100.52"), 0, "unparseable item is skipped");
    // the newest entry that could be read
    assert_eq!(h.since("nvr1"), at("21"));

    // the next poll still sees the broken entries in its overlap, works,
    // and counts nothing twice
    h.add("10:02:10", "198.51.100.60");
    h.cycle("10:02:30");
    assert_eq!(h.fails("198.51.100.60"), 1);
    assert_eq!(h.fails("198.51.100.50"), 1);
    assert_eq!(h.fails("198.51.100.51"), 1);
    assert_eq!(h.since("nvr1"), format!("{}10:02:10", DAY));
}

/// C5: a page that cannot be parsed at all, again and again.
#[test]
fn unreadable_log_window_is_skipped_after_ten_polls() {
    let mut h = Harness::new(false);
    h.fake.lock().unwrap().poison = Some(format!("{}10:00:30", DAY));
    for i in 0..9 {
        h.advance(30);
        assert_eq!(h.engine.nvrs[0].failed_polls, i + 1);
        assert_eq!(h.since("nvr1"), format!("{}10:00:00", DAY));
    }
    h.advance(30); // the 10th failure
    assert_eq!(h.since("nvr1"), format!("{}10:05:00", DAY));
    assert_eq!(h.engine.nvrs[0].failed_polls, 0);
    assert_eq!(h.engine.nvrs[0].retry_after, 0, "not an auth problem");

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
    assert!(h.engine.state.fails.is_empty());
    assert!(h.engine.state.pending.is_empty());
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
        h.engine.state.fails.is_empty(),
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
    assert!(h.engine.state.pending.is_empty());
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
    h.cycle("10:02:00");
    assert_eq!(h.fake.lock().unwrap().search_requests - before, 2);
    assert_eq!(h.fails(OWNER), 1);
    h.cycle("10:02:30");
    assert_eq!(h.fails(OWNER), 1);
    assert!(h.banned().is_empty());
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
        assert_eq!(h.engine.nvrs[0].retry_after, 0, "no auth backoff");
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
    assert!(h.engine.nvrs[0].retry_after > 0);
    assert_eq!(h.fake.lock().unwrap().refused_logins, 2);
}

/// C9: Basic and Digest offered together.
#[test]
fn basic_and_digest_challenges_together() {
    let mut h = Harness::raw(false);
    h.fake.lock().unwrap().basic_first = true;
    h.tick();
    assert_eq!(h.engine.nvrs[0].retry_after, 0);
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
    assert_eq!(h.engine.state.pending.len(), 2);
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
    assert_eq!(h.engine.state.pending.len(), 1);
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
    assert!(h.engine.state.pending.is_empty());
}

/// Bans that cannot be applied are not kept for ever.
#[test]
fn pending_ban_expires_after_bantime() {
    let mut h = Harness::new(false);
    h.fake.lock().unwrap().router_down = true;
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert_eq!(h.engine.state.pending.len(), 1);
    h.set_host(h.host + 86400 + 60);
    h.tick();
    assert!(h.engine.state.pending.is_empty());
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
    assert_eq!(h.engine.state.pending.len(), 3);
    assert!(h.engine.state.recent_bans.is_empty());
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
        assert!(h.engine.state.nvr["nvr1"].seen.len() >= 3200);
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
    assert!(h.engine.firewall.is_none());
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
    assert!(h.engine.state.banned.contains_key(&attacker()));
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
    assert!(h.engine.state.banned.contains_key(&attacker()));
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
    let until = h.engine.state.banned[&attacker()];
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
    assert_eq!(h.engine.cfg.findtime, 3600);
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
    assert_eq!(h.engine.state.pending.len(), 1);
    h.set_host(h.host + 23 * 3600);
    h.tick();
    assert_eq!(h.engine.state.pending.len(), 1);
    h.set_host(h.host + 3600 + 60);
    h.tick();
    assert!(h.engine.state.pending.is_empty());
    assert!(h.banned().is_empty());
}

// ---------------------------------------------------------- health alerts

const WARN: &str = "\u{26a0}\u{fe0f} hik-f2b: ";
const OK: &str = "\u{2705} hik-f2b: ";

#[test]
fn nvr_outage_is_alerted_once_then_recovery() {
    let mut h = Harness::new(true);
    h.fake.lock().unwrap().nvr_down = true;
    run(&mut h, 20, 30); // first failure at 10:00:30, now 10:10:00
    assert!(telegram_texts(&h).is_empty(), "alerted before alert_after");
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
    run(&mut h, 20, 30);
    assert_eq!(telegram_texts(&h).len(), 1, "alerted more than once");
    assert_eq!(h.engine.alerted_problems(), vec!["nvr:nvr1"]);

    h.fake.lock().unwrap().nvr_down = false;
    h.advance(30); // 10:21:00
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 2, "{:?}", texts);
    assert_eq!(
        texts[1],
        format!("{}nvr1 is readable again (after 20 min)", OK)
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
    h.cycle("10:02:00"); // the ban fails: the outage starts now
    assert_eq!(h.engine.state.pending.len(), 1);
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
    run(&mut h, 40, 30);
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
        "/rest/ip/firewall/raw?src-address-list=cctv_ban&.proplist=.id%2Cdisabled"
    );
    assert_eq!(
        queries[1],
        "/rest/ip/firewall/filter?src-address-list=cctv_ban&.proplist=.id%2Cdisabled"
    );

    // a disabled rule does not count
    h.fake
        .lock()
        .unwrap()
        .rules
        .push(("filter", "cctv_ban".to_string(), true));
    h.advance(300); // 10:20
    assert_eq!(telegram_texts(&h).len(), 1);
    // an enabled one in filter does
    h.fake
        .lock()
        .unwrap()
        .rules
        .push(("filter", "cctv_ban".to_string(), false));
    h.advance(300); // 10:25
    let texts = telegram_texts(&h);
    assert_eq!(texts.len(), 2, "{:?}", texts);
    assert_eq!(
        texts[1],
        format!("{}banned addresses are blocked again (after 20 min)", OK)
    );
}

/// The rule check against replies shaped like RouterOS 7.18.1's: enabled
/// `raw` rules have no `disabled` member, `filter` rules always have one.
#[test]
fn rule_check_reads_the_disabled_member_as_the_router_prints_it() {
    use hik_f2b::action::HealthError;
    let h = Harness::new(false);
    let set = |rules: &[(&'static str, bool)]| {
        h.fake.lock().unwrap().rules = rules
            .iter()
            .map(|(t, d)| (*t, "cctv_ban".to_string(), *d))
            .collect();
    };
    let check = || h.engine.firewall.as_ref().unwrap().check();

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
        Ok("1 enabled rule(s) in /ip/firewall/filter with src-address-list=cctv_ban".to_string())
    );

    // only disabled rules, in both tables
    set(&[("raw", true), ("filter", true)]);
    assert!(matches!(check(), Err(HealthError::NotEnforced(_))));
    // a rule for another list does not count
    h.fake.lock().unwrap().rules = vec![("raw", "other".to_string(), false)];
    assert!(matches!(check(), Err(HealthError::NotEnforced(_))));
}

#[test]
fn missing_drop_rule_is_reminded_daily() {
    let mut h = Harness::new(true);
    h.fake.lock().unwrap().rules.clear();
    run(&mut h, 3, 300); // checks at 10:05, 10:10, 10:15: alert
    assert_eq!(telegram_texts(&h).len(), 1);
    run(&mut h, 23, 3600);
    h.advance(3300); // one day after the alert, less 5 minutes
    assert_eq!(telegram_texts(&h).len(), 1);
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
    h.cycle("10:02:00"); // refused: the problem starts now
    assert_eq!(h.engine.state.pending.len(), 1);
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
    assert!(h.engine.firewall.as_ref().unwrap().check().is_ok());

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
    assert!(h.engine.state.pending.is_empty());
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
    assert!(h.engine.state.pending.is_empty());
    assert_eq!(
        h.fake.lock().unwrap().lookups,
        vec!["list=cctv_ban&address=198.51.100.4&.proplist=.id"]
    );
}

#[test]
fn refused_ban_of_an_unlisted_address_is_retried() {
    let mut h = Harness::new(false);
    h.fake.lock().unwrap().router_down = true; // every PUT gets HTTP 500
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert!(h.banned().is_empty());
    assert_eq!(h.engine.state.pending.len(), 1);
    assert_eq!(h.fake.lock().unwrap().lookups.len(), 1);
}

#[test]
fn todays_wording_needs_no_lookup() {
    let mut h = Harness::new(false);
    h.fake.lock().unwrap().bans.push(ATTACKER.to_string());
    h.burst("10:01", ATTACKER, 5);
    h.cycle("10:02:00");
    assert!(h.engine.state.pending.is_empty());
    assert!(h.fake.lock().unwrap().lookups.is_empty());
}

// ------------------------------------------------------------------ --check

#[test]
fn check_command_reports_each_item_and_changes_nothing() {
    use hik_f2b::health::Status;
    let mut h = Harness::with(Opts {
        telegram: true,
        second_nvr: true,
        ..Default::default()
    });
    let slow = h.fake2.clone().unwrap();
    slow.lock().unwrap().nvr_auth_ok = false;
    h.burst("10:01", ATTACKER, 5); // not read by --check
    let saved = h.engine.state.serialize();

    let lines = h.engine.check_all();
    let summary: Vec<(String, Status)> = lines
        .iter()
        .map(|l| (l.item.clone(), l.status.clone()))
        .collect();
    assert_eq!(
        summary,
        vec![
            ("nvr nvr1".to_string(), Status::Ok),
            ("nvr nvr2".to_string(), Status::Failed),
            ("firewall".to_string(), Status::Ok),
            ("telegram".to_string(), Status::Ok),
            ("country database".to_string(), Status::Off),
        ]
    );
    assert!(
        lines[0].detail.contains("device time 2026-01-10T10:00:00Z"),
        "{}",
        lines[0]
    );
    assert_eq!(
        lines[1].to_string(),
        "FAILED   nvr nvr2: login rejected (HTTP 401)"
    );
    assert_eq!(
        lines[2].detail,
        "1 enabled rule(s) in /ip/firewall/raw with src-address-list=cctv_ban"
    );

    h.fake.lock().unwrap().rules.clear();
    let lines = h.engine.check_all();
    assert_eq!(lines[2].status, Status::Failed);

    // nothing banned, sent or remembered
    assert_eq!(h.engine.state.serialize(), saved);
    assert!(h.banned().is_empty());
    assert_eq!(h.fake.lock().unwrap().tg_attempts, 0);
    assert!(h.engine.alerted_problems().is_empty());
    assert_eq!(h.engine.nvrs[1].retry_after, 0, "no backoff from --check");

    let mut h = Harness::with(Opts {
        mikrotik: false,
        ..Default::default()
    });
    let lines = h.engine.check_all();
    assert_eq!(lines[1].status, Status::Off);
    assert_eq!(lines[2].status, Status::Off);
    assert_eq!(h.fake.lock().unwrap().router_requests, 0);
}

// ------------------------------------------------------------- country_db

const FLAG_MD: &str = "\u{1f1f2}\u{1f1e9}";

/// Writes a synthetic country database (198.51.100.0/24 = MD) into the
/// harness directory and points the engine at it.
fn with_country_db(h: &mut Harness) -> PathBuf {
    let path = h.dir.join("country.mmdb");
    std::fs::write(&path, mmdb::simple(28, 6, "MD")).unwrap();
    h.engine.cfg.country_db = Some(path.clone());
    path
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
    h.engine.cfg.dry_run = true;
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
    h.engine.cfg.country_db = Some(path.clone());
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
    assert_eq!(h.engine.state.pending.len(), 1);
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
    assert!(h.engine.cfg.country_db.is_none());
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
    let line = |h: &mut Harness| h.engine.check_all().pop().unwrap();
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
