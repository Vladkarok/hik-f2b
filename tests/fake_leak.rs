//! A dropped `Harness` releases what its fakes started: their listener and
//! connection threads end and their listening sockets close. Without that,
//! a long simulation run piles up threads until the system refuses to start
//! another one.
//!
//! The fakes count their own threads and listeners (`fake::live_threads`,
//! `fake::open_listeners`), which works on every platform; on Linux the
//! process's threads and open file descriptors are checked as well, and no
//! accept may fail. This file holds one test, so that no other test's
//! fakes run in its process meanwhile.

#[path = "support/fake.rs"]
mod fake;

use fake::{Harness, Opts, ATTACKER};
use hik_f2b::util;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// Harnesses created and dropped.
const HARNESSES: usize = 200;
/// The most fake threads one harness here may have: one listener and a few
/// connections for each of its two fakes.
const MAX_THREADS: usize = 16;

/// The threads of this process, where the system tells it.
fn os_threads() -> Option<usize> {
    if cfg!(target_os = "linux") {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let line = status.lines().find(|l| l.starts_with("Threads:"))?;
        line["Threads:".len()..].trim().parse().ok()
    } else {
        None
    }
}

/// The open file descriptors of this process, where the system tells it.
fn os_fds() -> Option<usize> {
    if cfg!(target_os = "linux") {
        Some(std::fs::read_dir("/proc/self/fd").ok()?.count())
    } else {
        None
    }
}

/// Sends one request on a connection of its own and reads the whole reply,
/// so that the thread serving it then waits for the next request.
fn hold_connection(port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .write_all(b"GET /nothing HTTP/1.1\r\nHost: fake\r\n\r\n")
        .unwrap();
    let mut reply = Vec::new();
    let mut buf = [0u8; 256];
    while !reply.ends_with(b"not found") {
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0, "the fake closed the connection");
        reply.extend_from_slice(&buf[..n]);
    }
    stream
}

#[test]
fn dropped_harnesses_release_their_threads_and_listeners() {
    assert_eq!(
        fake::live_threads(),
        0,
        "fake threads before the first harness"
    );
    assert_eq!(
        fake::open_listeners(),
        0,
        "listeners before the first harness"
    );
    // the engine's log is kept, not printed
    util::capture_log();
    let base = os_threads();
    // Taken after the first harness, so that what the process opens once
    // and keeps does not count.
    let mut base_fds = None;
    for i in 0..HARNESSES {
        let mut h = Harness::with(Opts {
            telegram: i % 2 == 0,
            mikrotik: i % 4 != 3,
            second_nvr: i % 3 == 0,
            ..Default::default()
        });
        // A ban and its notification: connections to the router and to
        // Telegram as well as to the NVR.
        h.burst("10:01", ATTACKER, 5);
        h.cycle("10:02:00");
        if i % 4 != 3 {
            assert_eq!(h.banned(), vec![ATTACKER.to_string()], "harness {}", i);
        }
        if i % 5 == 0 {
            // a restart drops the old engine's connections
            h.restart();
            h.advance(30);
        }
        // A connection held by a client other than the engine, which only
        // the fake can end. On Windows a shutdown does not wake a thread
        // blocked reading, so it is held on the other platforms only.
        let held = (!cfg!(windows) && i % 2 == 1).then(|| hold_connection(h.port));
        let listeners = if i % 3 == 0 { 2 } else { 1 };
        assert_eq!(fake::open_listeners(), listeners, "harness {}", i);
        let live = fake::live_threads();
        assert!(
            (listeners..=MAX_THREADS).contains(&live),
            "harness {}: {} live fake threads",
            i,
            live
        );
        drop(h);
        assert_eq!(
            fake::live_threads(),
            0,
            "harness {}: threads after the drop",
            i
        );
        assert_eq!(
            fake::open_listeners(),
            0,
            "harness {}: listeners after the drop",
            i
        );
        drop(held);
        let _ = util::captured_log();
        if i == 0 {
            base_fds = os_fds();
        }
    }
    assert!(
        fake::peak_threads() <= MAX_THREADS,
        "{} fake threads at the peak",
        fake::peak_threads()
    );
    if let Some(base) = base {
        // A joined thread can still be listed for a moment: the kernel
        // wakes the join before it has removed the thread. Wait for that,
        // for at most a few seconds (200 leaked threads would not go away).
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut now = os_threads();
        while now != Some(base) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
            now = os_threads();
        }
        assert_eq!(now, Some(base), "threads of the process after the drops");
    }
    // Sockets, state files: a harness leaves no descriptor open.
    assert_eq!(
        os_fds(),
        base_fds,
        "open file descriptors after the drops (after the first: {:?})",
        base_fds
    );
    assert_eq!(fake::accept_errors(), 0, "failed accepts on the fakes");
}
