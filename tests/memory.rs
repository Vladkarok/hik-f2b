//! The heap that hik-f2b needs at the bounds of its state (issue 9), told
//! by a counting allocator. Ignored by default; run it with
//!
//! ```text
//! cargo test --release --test memory -- --ignored --nocapture
//! ```
//!
//! For 2, 4 and 8 NVRs (the most a config may have) it writes a state file
//! at the bounds (every `seen` at the share of its NVR, every bound of the
//! ledger reached, with the longest lines), then loads it as the service
//! does, polls each NVR once
//! with a full window (one search of 3200 entries from the fake NVR), and
//! saves it. It reports the most heap in use meanwhile, above what was in
//! use before the load.
//!
//! What the number includes: every heap allocation of the process, as
//! requested from the allocator, so the fake NVR's answers too (it runs in
//! this process; its log is set up before the count starts). What it does
//! not include: the allocator's own overhead and fragmentation, the
//! program's code and static data, thread stacks, and the memory the
//! kernel counts for the files hik-f2b reads and writes. The resident
//! memory of the service is this plus about what it uses with an empty
//! state.
//!
//! The counting allocator needs `unsafe`: `GlobalAlloc` is an unsafe trait.
//! It only counts and passes every call to the system allocator.

#[path = "support/fake.rs"]
mod fake;

use fake::{device, Entry, Harness, Opts, SKEW};
use hik_f2b::config::Config;
use hik_f2b::nvr::Nvr;
use hik_f2b::reader::{seen_share, LogReader, Poll};
use hik_f2b::state::State;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;

static IN_USE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call goes to `System` unchanged; the counters are atomics.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let now = IN_USE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        IN_USE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            if new_size >= layout.size() {
                let grow = new_size - layout.size();
                let now = IN_USE.fetch_add(grow, Ordering::Relaxed) + grow;
                PEAK.fetch_max(now, Ordering::Relaxed);
            } else {
                IN_USE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        p
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

const MIB: f64 = 1024.0 * 1024.0;

/// The longest NVR name the config allows (32 characters).
fn long_name(i: usize) -> String {
    format!("{:-<32}", format!("nvr{}", i))
}

/// An address of 15 characters, for `i` below 1,000,000.
fn long_address(i: usize) -> String {
    format!(
        "200.{}.{}.{}",
        100 + i / 10_000 % 100,
        100 + i / 100 % 100,
        100 + i % 100
    )
}

/// The state file at its bounds for the NVRs `names`, each at `seen` seen
/// entries, its cursor at `since` (device time) with the offset `SKEW`.
fn full_state(names: &[String], seen: usize, since: i64) -> String {
    let max_time = 253_402_300_799i64;
    let mut text = String::from("hik-f2b-state 2\n");
    for name in names {
        text.push_str(&format!("nvr {} {} {}\n", name, since, SKEW));
        let mut keys: Vec<String> = (0..seen)
            .map(|i| format!("{:032x}", u128::MAX - i as u128))
            .collect();
        keys.sort();
        for key in keys {
            text.push_str(&format!("seen {} {} 1000000\n", name, key));
        }
    }
    // the bounds of src/ledger.rs: 10,000 addresses with 20 failure times
    // each, 100,000 remembered bans, 1000 waiting, 10,000 recent bans
    for i in 0..10_000 {
        for _ in 0..20 {
            text.push_str(&format!("fail {} {}\n", long_address(i), max_time));
        }
    }
    for i in 0..100_000 {
        text.push_str(&format!("ban {} {}\n", long_address(i), max_time));
    }
    for i in 0..1000 {
        text.push_str(&format!(
            "pending {} {} 1000000 {} {}\n",
            long_address(i),
            max_time,
            names[0],
            "u".repeat(32)
        ));
    }
    for _ in 0..10_000 {
        text.push_str(&format!("rate {}\n", max_time));
    }
    text
}

#[test]
#[ignore]
fn peak_heap_at_the_bounds() {
    let h = Harness::build(Opts {
        mikrotik: false,
        ..Default::default()
    });
    let host = h.host;
    let now = host + SKEW;
    {
        // 3300 entries in the minute before the device's time: one search
        // reads 3200 of them
        let mut f = h.fake.lock().unwrap();
        for n in 0..3300 {
            f.entries.push(Entry {
                ts: device(now - 60 + (n as i64) * 60 / 3300),
                minor: "illlegealAccess".to_string(),
                ip: "192.168.1.50".to_string(),
                user: format!("u{:04}", n).into_bytes(),
            });
        }
        f.entries.sort();
    }
    println!("| NVRs | seen per NVR | state file | heap after the load | peak heap |");
    println!("| --- | --- | --- | --- | --- |");
    for nvrs in [2, 4, 8] {
        let names: Vec<String> = (1..=nvrs).map(long_name).collect();
        let mut ini = format!(
            "[general]\nstate_file = {}\n",
            h.dir.join("state").display()
        );
        for name in &names {
            ini.push_str(&format!(
                "[nvr:{}]\nurl = http://127.0.0.1:{}\nuser = f2b\npassword = secret\n",
                name, h.port
            ));
        }
        let cfg = Config::parse(&ini).unwrap();
        let seen = seen_share(cfg.nvrs.len());
        let path = h.dir.join(format!("state-{}", nvrs));
        let text = full_state(&names, seen, now - 10);
        std::fs::write(&path, &text).unwrap();
        let file = text.len();
        drop(text);
        let mut readers: Vec<LogReader> = cfg
            .nvrs
            .iter()
            .map(|n| LogReader::new(&n.name, Nvr::new(n).unwrap()))
            .collect();

        let before = IN_USE.load(Ordering::SeqCst);
        PEAK.store(before, Ordering::SeqCst);
        let mut state = State::load(&path).unwrap();
        let loaded = IN_USE.load(Ordering::SeqCst) - before;
        for reader in &mut readers {
            match reader.poll(&mut state.cursors, &cfg, host as u64) {
                Poll::Read(logins) => assert!(logins.count() > 3000),
                _ => panic!("{} not read", reader.name()),
            }
        }
        state.save(&path).unwrap();
        let peak = PEAK.load(Ordering::SeqCst) - before;
        println!(
            "| {} | {} | {:.1} MiB | {:.1} MiB | {:.1} MiB |",
            nvrs,
            seen,
            file as f64 / MIB,
            loaded as f64 / MIB,
            peak as f64 / MIB
        );
        drop(state);
        drop(readers);
    }
}
