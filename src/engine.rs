//! The decision logic: read new failures, count them, ban, notify.
//!
//! Two clocks are involved. Each NVR's log and read cursor are in that
//! device's local wall-clock time, which DST changes and which an RTC reset
//! can put decades off; the NVR's log reader (`reader.rs`) keeps that to
//! itself. Everything that is counted or compared across NVRs (failure
//! times, `findtime`, bans, the rate limit) is in host time; the reader
//! converts an NVR's entries with that NVR's current offset. The host time
//! is passed in (`cycle_at`), so tests can drive both clocks.
//!
//! Along the way the engine tells `health::Health` how each NVR read, each
//! firewall check and each ban attempt went, how the ban loop ended and when
//! the poll ends; that module decides which health check this opens or ends
//! and when it is worth an alert.

use crate::action::{render, BanError, BanInfo, Firewall, HealthError, Notifier};
use crate::config::{Config, DEFAULT_MESSAGE};
use crate::country::{self, Code};
use crate::health::{BanAttempt, BansEnded, CheckLine, Health, Kind, Notice, NvrRead, Status};
use crate::ledger::{Outcome, Rules, Turn};
use crate::mikrotik::Mikrotik;
use crate::nvr::{Nvr, NvrError, Search};
use crate::outbox::Outbox;
use crate::reader::{LogReader, Login, Logins, Poll};
use crate::state::State;
use crate::telegram::Telegram;
use crate::util::{self, host_i64};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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

pub struct Engine {
    pub cfg: Config,
    pub state: State,
    pub readers: Vec<LogReader>,
    pub firewall: Option<Box<dyn Firewall>>,
    pub outbox: Outbox,
    template: String,
    health: Health,
    /// The reason the last country lookup failed, if it did: a failure is
    /// logged when its reason changes, a recovery once.
    country_failure: Option<String>,
    /// Set (by a signal handler) when the service is to stop. A cycle
    /// looks at it between its steps (see `cycle_at`).
    stop: Arc<AtomicBool>,
}

/// Counts one failed login (host time) in the ledger, which queues the ban
/// when the limit is reached.
fn register(login: &Login, host_now: i64, rules: &Rules, state: &mut State, report_once: bool) {
    let user = util::sanitize(&login.user, 32);
    let ip = match login.ip {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(ip) => {
            crate::info!(
                "{}: failed login from {} (user={:?}): IPv6 is not handled",
                login.nvr,
                ip,
                user
            );
            return;
        }
    };
    state
        .ledger
        .failed_login(rules, ip, login.at, host_now, &login.nvr, user, report_once);
}

impl Engine {
    /// An engine with the router and Telegram clients the configuration
    /// asks for.
    pub fn new(cfg: Config, state: State) -> Result<Engine, String> {
        let firewall: Option<Box<dyn Firewall>> = match &cfg.mikrotik {
            Some(m) => Some(Box::new(Mikrotik::new(m)?)),
            None => None,
        };
        let notifier: Option<Box<dyn Notifier>> = match &cfg.telegram {
            Some(t) => Some(Box::new(Telegram::new(t)?)),
            None => None,
        };
        Engine::with_parts(cfg, state, firewall, notifier)
    }

    /// An engine with the given firewall and notifier (either may be absent).
    pub fn with_parts(
        cfg: Config,
        state: State,
        firewall: Option<Box<dyn Firewall>>,
        notifier: Option<Box<dyn Notifier>>,
    ) -> Result<Engine, String> {
        let readers = cfg
            .nvrs
            .iter()
            .map(|nvr| Nvr::new(nvr).map(|client| LogReader::new(&nvr.name, client)))
            .collect::<Result<Vec<_>, _>>()?;
        let template = cfg
            .telegram
            .as_ref()
            .map(|t| t.message.clone())
            .unwrap_or_else(|| DEFAULT_MESSAGE.replace("\\n", "\n"));
        let mut engine = Engine {
            health: Health::new(cfg.alert_after, cfg.max_bans_per_hour),
            cfg,
            state,
            readers,
            firewall,
            outbox: Outbox::new(notifier),
            template,
            country_failure: None,
            stop: Arc::new(AtomicBool::new(false)),
        };
        engine.state.ledger.fit(&Rules::of(&engine.cfg));
        Ok(engine)
    }

    /// The flag that stops the service: set it (from a signal handler) and
    /// the current cycle ends after its current step, see `cycle_at`.
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    fn stopping(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// The service: a cycle every `poll_interval` (or only one, with
    /// `once`) until the stop flag is set. The state is saved after every
    /// cycle in which it changed, also after a cycle that a stop cut short,
    /// so what that cycle learned is not lost.
    pub fn run(&mut self, state_file: &Path, once: bool) {
        // A hash of what was saved: the state is written out (line by line)
        // only when it changed, and never held as a second copy in memory.
        let mut saved = self.state.digest();
        while !self.stopping() {
            self.cycle();
            let current = self.state.digest();
            if current != saved {
                match self.state.save(state_file) {
                    Ok(()) => saved = current,
                    Err(e) => crate::error!(
                        "cannot save state to {}: {}",
                        state_file.display(),
                        e.kind()
                    ),
                }
            }
            if once {
                break;
            }
            let deadline = Instant::now() + Duration::from_secs(self.cfg.poll_interval);
            while !self.stopping() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(250));
            }
        }
    }

    /// Runs the firewall health check once at startup and logs the result;
    /// the first periodic check follows `health::HEALTH_CHECK_INTERVAL`
    /// later.
    /// Returns whether the firewall answered (so that more can be asked of
    /// it without waiting for a second timeout).
    pub fn startup_check(&mut self, host_now: u64) -> bool {
        match self.check_firewall(host_now) {
            None => false,
            Some(Ok(found)) => {
                crate::info!("firewall check ok: {}", found);
                true
            }
            Some(Err(e)) => {
                crate::error!(
                    "firewall check failed: {} (bans will keep being retried)",
                    e
                );
                matches!(e, HealthError::NotEnforced(_))
            }
        }
    }

    /// Logs which country database is configured, or why it cannot be
    /// read. Either way the service runs; without the file bans simply
    /// carry no country.
    pub fn startup_country(&mut self) {
        let Some(path) = self.cfg.country_db.clone() else {
            return;
        };
        match country::info(&path) {
            Ok(info) => crate::info!("country database: {}", info.describe()),
            Err(e) => {
                crate::warn!(
                    "country database cannot be read, bans go on without a country: {}",
                    e
                );
                self.country_failure = Some(e);
            }
        }
    }

    /// The country of `ip`, if `country_db` is set and knows it. A failed
    /// lookup never holds up a ban: it is logged when the reason changes
    /// (not on every retry of the same ban), and once when lookups work
    /// again. It is not a health alert.
    fn country(&mut self, ip: Ipv4Addr) -> Option<Code> {
        let path = self.cfg.country_db.as_ref()?;
        match country::lookup(path, ip) {
            Ok(code) => {
                if self.country_failure.take().is_some() {
                    crate::info!("country lookups work again");
                }
                code
            }
            Err(e) => {
                if self.country_failure.as_deref() != Some(e.as_str()) {
                    crate::warn!("country lookup failed, bans go on without a country: {}", e);
                    self.country_failure = Some(e);
                }
                None
            }
        }
    }

    /// One health check of the firewall; the outcome goes to health.
    fn check_firewall(&mut self, host_now: u64) -> Option<Result<String, HealthError>> {
        let result = self.firewall.as_ref()?.check();
        self.health.firewall_checked(&result, host_now);
        Some(result)
    }

    /// The periodic firewall check, at most once per cycle, when health
    /// says it is due (see `Health::check_due`).
    fn periodic_check(&mut self, host_now: u64) {
        if !self.health.check_due(host_now) {
            return;
        }
        match self.check_firewall(host_now) {
            Some(Err(e)) => crate::warn!("firewall check failed: {}", e),
            Some(Ok(found)) => crate::debug!("firewall check ok: {}", found),
            None => {}
        }
    }

    /// Logs the health notices that are due and queues them for the chat.
    fn report_health(&mut self, host_now: u64) {
        let to_chat = self.outbox.notifier.is_some()
            && self.cfg.telegram.as_ref().is_none_or(|t| t.health_alerts);
        for notice in self.health.due(host_now) {
            log_notice(&notice);
            if to_chat {
                self.outbox.queue_notification(notice.text());
            }
        }
    }

    /// Problems that have been alerted and still persist, by key (for
    /// tests and diagnostics).
    pub fn alerted_problems(&self) -> Vec<String> {
        self.health.alerted()
    }

    /// `--check` at the current host time.
    pub fn check_all(&mut self) -> Vec<CheckLine> {
        self.check_all_at(util::unix_now())
    }

    /// `--check`: every health check once. Only reads: the state, the
    /// alerts and the firewall are left as they are, and nothing is sent.
    /// `host_now` is the host's Unix time.
    pub fn check_all_at(&mut self, host_now: u64) -> Vec<CheckLine> {
        let mut out = Vec::new();
        let meta_id = self.cfg.meta_id.clone();
        for reader in self.readers.iter_mut() {
            let nvr = reader.client();
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
        let (status, detail) = match &self.firewall {
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
        let (status, detail) = match &self.cfg.telegram {
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
        let (status, detail) = match &self.cfg.country_db {
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

    /// One full pass at the current host time.
    pub fn cycle(&mut self) {
        self.cycle_at(util::unix_now());
    }

    /// One full pass: poll every NVR, apply bans, send notifications.
    /// `host_now` is the host's Unix time.
    ///
    /// The stop flag is looked at before each step that may wait for a
    /// device: each NVR's poll, each ban, the firewall check and each
    /// notification. Once it is set the cycle skips what is left of these;
    /// what earlier steps learned (read positions, counted failed logins,
    /// waiting bans) is in the state, which the caller saves.
    pub fn cycle_at(&mut self, host_now: u64) {
        let now = host_i64(host_now);
        let report_once = self.firewall.is_none() || self.cfg.dry_run;
        for i in 0..self.readers.len() {
            if self.stopping() {
                self.health
                    .nvr_polled(self.readers[i].name(), NvrRead::NotTried, host_now);
                break;
            }
            match self.readers[i].poll(&mut self.state.cursors, &self.cfg, host_now) {
                Poll::BackingOff => {
                    self.health
                        .nvr_polled(self.readers[i].name(), NvrRead::NotTried, host_now);
                }
                Poll::Failed(NvrError::Auth(e)) => {
                    crate::error!(
                        "{}: login to the NVR was rejected ({}). Check the user, the password and the \
                         'Remote: Log Search' permission. Next try in {} s.",
                        self.readers[i].name(),
                        e,
                        self.cfg.auth_backoff
                    );
                    self.health.nvr_polled(
                        self.readers[i].name(),
                        NvrRead::LoginRejected(&e),
                        host_now,
                    );
                }
                Poll::Failed(NvrError::Other(e)) => {
                    crate::warn!("{}: poll failed: {}", self.readers[i].name(), e);
                    self.health
                        .nvr_polled(self.readers[i].name(), NvrRead::Failed(&e), host_now);
                }
                Poll::Read(logins) => {
                    self.health
                        .nvr_polled(self.readers[i].name(), NvrRead::Read, host_now);
                    self.count(logins, now, report_once);
                }
            }
        }
        if !self.stopping() {
            self.flush_pending(host_now);
        }
        self.health.poll_ended(host_now);
        if !self.stopping() {
            self.periodic_check(host_now);
        }
        self.report_health(host_now);
        self.outbox.flush_notifications(host_now, &self.stop);
        self.cleanup(host_now);
        if self.stopping() {
            crate::info!(
                "stop requested: the rest of this poll is skipped; waiting bans and \
                 notifications wait for the next start"
            );
        }
    }

    /// Counts one NVR's new failed logins (in host time, inside the
    /// counting window) and queues the bans they call for.
    fn count(&mut self, logins: Logins, now: i64, report_once: bool) {
        for login in logins {
            let rules = Rules::of(&self.cfg);
            register(&login, now, &rules, &mut self.state, report_once);
        }
    }

    /// Applies waiting bans. The firewall turning out to be unusable
    /// (unreachable, refusing our login or answering with an error) ends the
    /// attempts for this cycle.
    fn flush_pending(&mut self, now: u64) {
        let bantime = self.cfg.bantime;
        let due = self.state.ledger.due(&Rules::of(&self.cfg), now);
        let mut end = BansEnded::Complete;
        for ip in due {
            if self.stopping() {
                end = BansEnded::Stopped;
                break;
            }
            let p = match self.state.ledger.next_ban(&Rules::of(&self.cfg), ip) {
                Turn::Ban(p) => p,
                Turn::Gone => continue,
                Turn::RateLimited => {
                    end = BansEnded::RateLimited;
                    break;
                }
            };
            // Display only, and looked up after every decision is made.
            let code = self.country(ip);
            // At the end: after the fixed-format time, where the user name
            // (attacker-chosen, up to 32 characters) cannot reach. The whole
            // comment stays within 110 characters.
            let comment = util::sanitize(
                &format!(
                    "hik-f2b {} user={} {}{}",
                    p.nvr,
                    p.user,
                    util::fmt_ts(p.ts),
                    code.map(|c| format!(" country={}", c)).unwrap_or_default()
                ),
                120,
            );
            // `198.51.100.7 [MD]` in the log
            let shown = match code {
                Some(c) => format!("{} [{}]", ip, c),
                None => ip.to_string(),
            };
            let duration = bantime.phrase();
            // (what happened, how it ended for the ledger, worth a notification)
            let (action, outcome, notify) = match &self.firewall {
                None => {
                    crate::warn!(
                        "DETECTED {} (no firewall configured, not banned) ({})",
                        shown,
                        comment
                    );
                    (
                        "detected, no firewall configured".to_string(),
                        Outcome::Reported,
                        true,
                    )
                }
                Some(_) if self.cfg.dry_run => {
                    crate::warn!("DRY RUN: would ban {} {} ({})", shown, duration, comment);
                    (
                        format!("would be banned {} (dry run)", duration),
                        Outcome::Reported,
                        true,
                    )
                }
                Some(fw) => match fw.ban(ip, bantime, &comment) {
                    Err(BanError::Refused(e)) => {
                        crate::error!("cannot ban {} on {}, will retry: {}", ip, fw.describe(), e);
                        self.health
                            .ban_tried(BanAttempt::Refused { ip, error: &e }, now);
                        (String::new(), Outcome::NotApplied, false)
                    }
                    Err(e) => {
                        // The firewall cannot be reached, refuses our login
                        // or answers with an error: every further attempt
                        // would fail the same way (an unreachable one only
                        // after the same timeout, holding up the next poll).
                        crate::error!(
                            "cannot ban {} on {}, will retry next cycle: {}",
                            ip,
                            fw.describe(),
                            e
                        );
                        self.health
                            .ban_tried(BanAttempt::Unreachable(&e.to_string()), now);
                        end = BansEnded::CutShort;
                        break;
                    }
                    Ok(true) => {
                        self.health.ban_tried(BanAttempt::Accepted, now);
                        crate::warn!("BAN {} {} ({})", shown, duration, comment);
                        (format!("banned {}", duration), Outcome::Banned, true)
                    }
                    Ok(false) => {
                        // The router is the source of truth for bans. A
                        // listed address should not reach the NVR, unless
                        // these failures were logged just before our ban.
                        // The time of the ban is kept (`Ledger::outcome`), so an
                        // attacker that keeps going cannot hide this.
                        let banned_at = self.state.ledger.ban_began(&Rules::of(&self.cfg), ip);
                        let grace = self.cfg.poll_interval.saturating_mul(2).saturating_add(60);
                        if now.saturating_sub(banned_at.unwrap_or(0)) > grace {
                            crate::warn!(
                                "{} is already in {} but still reached the NVR; \
                                 if this repeats, check the firewall drop rule for that list",
                                ip,
                                fw.describe()
                            );
                            self.health.ban_tried(
                                BanAttempt::Bypassed {
                                    ip,
                                    list: &fw.describe(),
                                    banned_at,
                                    nvr: &p.nvr,
                                },
                                now,
                            );
                        } else {
                            crate::info!("{} is already in {}", ip, fw.describe());
                            self.health.ban_tried(BanAttempt::Listed, now);
                        }
                        (String::new(), Outcome::AlreadyListed, false)
                    }
                },
            };
            self.state
                .ledger
                .outcome(&Rules::of(&self.cfg), ip, now, outcome);
            if notify && self.outbox.notifier.is_some() {
                // The flag only goes to the chat.
                let country = code
                    .map(|c| format!(" ({} {})", c.flag(), c))
                    .unwrap_or_default();
                let text = render(
                    &self.template,
                    &BanInfo {
                        ip,
                        country: &country,
                        action: &action,
                        bantime: &bantime.label(),
                        nvr: &p.nvr,
                        user: &p.user,
                        count: p.count,
                        findtime: self.cfg.findtime,
                    },
                );
                self.outbox.queue_notification(text);
            }
        }
        self.health
            .bans_ended(end, self.state.ledger.waiting(), now);
    }

    fn cleanup(&mut self, host_now: u64) {
        self.state.ledger.cleanup(&Rules::of(&self.cfg), host_now);
    }

    /// Notifications waiting to be sent (for tests and diagnostics).
    pub fn queued_notifications(&self) -> usize {
        self.outbox.notifications.len()
    }
}

/// One log line per health notice: ERROR for an alert or a reminder, INFO
/// for a recovery.
fn log_notice(notice: &Notice) {
    let text = notice.text();
    // The log does without the symbol that starts the chat message.
    let text = text.split_once(' ').map_or(text.as_str(), |(_, rest)| rest);
    let key = notice.check.key();
    match notice.kind {
        Kind::Alert => crate::error!("health alert [{}]: {}", key, text),
        Kind::Reminder => crate::error!("health reminder [{}]: {}", key, text),
        Kind::Recovered => crate::info!("health recovered [{}]: {}", key, text),
        Kind::Unknown => crate::info!("health unknown [{}]: {}", key, text),
    }
}
