//! `--check`: every health check once, on clients of its own. It only
//! reads: nothing is banned, sent or remembered, and no engine is involved.

use crate::action::Firewall;
use crate::config::Config;
use crate::country;
use crate::health::{CheckLine, Status};
use crate::nvr::{Nvr, NvrError, Search};
use crate::own::OwnAddresses;
use crate::util::{self, host_i64};
use std::net::Ipv4Addr;

/// `--check` searches the log of the last day before the device time...
const CHECK_WINDOW: i64 = 86400;
/// ...and reads at most this many pages of it, so it stays quick on a busy
/// NVR. Two pages tell the page size and, mostly, the order.
const CHECK_PAGES: usize = 2;

/// The device clock against the host clock, for `--check`: what the log
/// reader subtracts from device times.
fn describe_offset(offset: i64) -> String {
    let abs = offset.unsigned_abs();
    let hms = format!("{}:{:02}:{:02}", abs / 3600, abs / 60 % 60, abs % 60);
    match offset {
        0 => "same as the host clock".to_string(),
        o if o > 0 => format!("{} ahead of the host clock", hms),
        _ => format!("{} behind the host clock", hms),
    }
}

/// What a `--check` search showed about the NVR's log: the order of the
/// entries (the log reader reads both, see `read_window` in `reader.rs`) and
/// the page size.
fn describe_log(search: &Search) -> String {
    let times: Vec<i64> = search.events.iter().filter_map(|ev| ev.ts).collect();
    let up = times.windows(2).any(|w| w[0] < w[1]);
    let down = times.windows(2).any(|w| w[0] > w[1]);
    let order = match (up, down) {
        (true, false) => "oldest first",
        (false, true) => "newest first",
        (false, false) => "order not known",
        (true, true) => "neither oldest nor newest first",
    };
    let page = match search.page_size {
        Some(n) => format!("{} entries per page", n),
        None => "page size not known".to_string(),
    };
    let mut out = format!("{}, {}", order, page);
    if !(up || down) || search.page_size.is_none() {
        out.push_str(&format!(
            " ({} entries read from the last 24 h)",
            search.events.len()
        ));
    }
    out
}

/// `--check`: every health check once, with the NVR clients `nvrs` (one per
/// `cfg.nvrs`, in that order) and the firewall, if there is one, and the
/// own addresses as `own` found them. Nothing is sent. `host_now` is the
/// host's Unix time.
pub fn check_all(
    cfg: &Config,
    nvrs: &mut [Nvr],
    firewall: Option<&dyn Firewall>,
    own: &OwnAddresses,
    host_now: u64,
) -> Vec<CheckLine> {
    let mut out = Vec::new();
    let meta_id = cfg.meta_id.clone();
    for nvr in nvrs.iter_mut() {
        // The device time proves that the NVR answers and accepts the
        // login; a search, that the user may search the log. The search
        // also shows what the engine relies on (see `describe_log`).
        let result = nvr.now().and_then(|now| {
            nvr.sample(
                now.saturating_sub(CHECK_WINDOW),
                now.saturating_add(60),
                &meta_id,
                CHECK_PAGES,
            )
            .map(|search| (now, search))
        });
        let (status, detail, log) = match result {
            Ok((now, search)) => (
                Status::Ok,
                format!(
                    "login accepted, device time {} ({}), log search works",
                    util::fmt_ts(now),
                    describe_offset(now.saturating_sub(host_i64(host_now)))
                ),
                Some(describe_log(&search)),
            ),
            Err(NvrError::Auth(e)) => (Status::Failed, format!("login rejected ({})", e), None),
            Err(NvrError::Other(e)) => (Status::Failed, e, None),
        };
        out.push(CheckLine {
            item: format!("nvr {}", nvr.name),
            status,
            detail,
        });
        if let Some(detail) = log {
            out.push(CheckLine {
                item: format!("nvr {} log", nvr.name),
                status: Status::Ok,
                detail,
            });
        }
    }
    let (status, detail) = match firewall {
        None => (Status::Off, "not configured (notify-only mode)".to_string()),
        Some(fw) => match fw.check() {
            Ok(found) => (Status::Ok, found),
            Err(e) => (Status::Failed, e.to_string()),
        },
    };
    out.push(CheckLine {
        item: "firewall".to_string(),
        status,
        detail,
    });
    // A look-up that failed leaves an address unprotected.
    let failures = own.failures();
    let (status, detail) = if failures.is_empty() {
        (Status::Ok, format!("{} (never banned)", own.describe()))
    } else {
        (
            Status::Failed,
            format!(
                "{}; look-up failed: {}",
                own.describe(),
                failures.join("; ")
            ),
        )
    };
    out.push(CheckLine {
        item: "own addresses".to_string(),
        status,
        detail,
    });
    let (status, detail) = match &cfg.telegram {
        None => (Status::Off, "not configured".to_string()),
        Some(t) => (
            Status::Ok,
            format!(
                "configured, health alerts {}; nothing sent (see --test-notify)",
                if t.health_alerts { "on" } else { "off" }
            ),
        ),
    };
    out.push(CheckLine {
        item: "telegram".to_string(),
        status,
        detail,
    });
    // A lookup proves that the search tree can be walked, not only that
    // the metadata can be read.
    let (status, detail) = match &cfg.country_db {
        None => (Status::Off, "not configured".to_string()),
        Some(path) => match country::info(path)
            .and_then(|info| country::lookup(path, Ipv4Addr::new(192, 0, 2, 1)).map(|_| info))
        {
            Ok(info) => (Status::Ok, info.describe()),
            Err(e) => (Status::Failed, e),
        },
    };
    out.push(CheckLine {
        item: "country database".to_string(),
        status,
        detail,
    });
    out
}
