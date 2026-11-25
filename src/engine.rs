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
//!
//! Notifications (about bans and from health) are rendered here and handed
//! to the outbox (`outbox.rs`) as texts; at the end of the poll the outbox
//! sends what it can.
//!
//! The own addresses (`own.rs`) are looked up again at the start of every
//! poll (a host name at most every `names::RESOLVE_EVERY`) and given to the
//! ledger with the rules. With every firewall check
//! the engine asks the router whether an own address is in the
//! address-list, and removes it if it is (`sweep_own`): the only ban
//! hik-f2b ever removes (ADR 0005). With a safe list, the same checks keep
//! the own address toward the router in it (`keep_safe`, ADR 0006).

use crate::action::{render, BanError, BanInfo, Firewall, HealthError, Kept, Notifier};
use crate::config::{Config, DEFAULT_MESSAGE};
use crate::country::{self, Code};
use crate::health::{
    self, BanAttempt, BansEnded, Health, Kind, Notice, NvrRead, OwnStuck, SafeWrite,
    HEALTH_CHECK_INTERVAL,
};
use crate::ledger::{Outcome, Rules, Turn, MAX_USER};
use crate::names::RESOLVE_EVERY;
use crate::nvr::{Nvr, NvrError};
use crate::outbox::Outbox;
use crate::own::OwnAddresses;
use crate::reader::{LogReader, Login, Logins, Poll};
use crate::state::State;
use crate::util::{self, host_i64};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The timeout of the own address's entry in the safe list: six firewall
/// checks. It is renewed at every check the router answers, so it outlives
/// five checks in a row that fail (a router that restarts, a network that
/// is down for 25 minutes), and an address that is no longer the host's
/// stays safe for at most half an hour.
pub const SAFE_TIMEOUT: u64 = 6 * HEALTH_CHECK_INTERVAL;

pub struct Engine {
    cfg: Config,
    state: State,
    readers: Vec<LogReader>,
    firewall: Option<Box<dyn Firewall>>,
    outbox: Outbox,
    template: String,
    health: Health,
    /// The reason the last country lookup failed, if it did: a failure is
    /// logged when its reason changes, a recovery once.
    country_failure: Option<String>,
    /// Set (by a signal handler) when the service is to stop. A cycle
    /// looks at it between its steps (see `cycle_at`).
    stop: Arc<AtomicBool>,
    /// The grace period after the engine started.
    startup: Startup,
    /// The own addresses, never banned.
    own: OwnAddresses,
    /// Own addresses found in the address-list and reported, that are not
    /// removed (a dry run, or a removal that failed): reported once while
    /// they stay listed.
    own_reported: BTreeSet<Ipv4Addr>,
    /// The own addresses toward the router that this engine has kept in
    /// the safe list (or, in a dry run, said it would keep).
    safe_kept: BTreeSet<Ipv4Addr>,
}

/// The first grace period (`Engine::grace`) after the engine started. The
/// ledger does not store when a ban began, it derives it from the
/// remembered end and the current `bantime` (see ADR 0003). After a restart
/// with another `bantime` that start is wrong, so an address found already
/// listed in this period is not taken for a bypass: a real bypass repeats,
/// and is reported from the next sighting after the period.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Startup {
    /// No poll yet.
    NotPolled,
    /// The period runs; the host time of the first poll.
    Since(u64),
    Over,
}

impl Startup {
    /// A poll at host time `now`. The first poll starts the period. It is
    /// over at the first poll more than `grace` after that one, or before
    /// it: a host clock that went back must not make it last longer than
    /// one grace period.
    fn polled(&mut self, now: u64, grace: u64) {
        if let Startup::NotPolled = self {
            *self = Startup::Since(now);
        } else if let Startup::Since(first) = *self {
            if now < first || now - first > grace {
                *self = Startup::Over;
            }
        }
    }

    fn running(self) -> bool {
        matches!(self, Startup::Since(_))
    }
}

/// Counts one failed login (host time) in the ledger, which queues the ban
/// when the limit is reached.
fn register(login: &Login, host_now: i64, rules: &Rules, state: &mut State, report_once: bool) {
    let user = util::sanitize(&login.user, MAX_USER);
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
    /// An engine that starts from `state` (what the state file held, or
    /// an empty state) with the given firewall and notifier (either may be
    /// absent; `main.rs` gives it the router and Telegram clients the
    /// configuration asks for) and the own addresses of `cfg`. It sets up a
    /// client per NVR of `cfg`.
    pub fn new(
        cfg: Config,
        state: State,
        firewall: Option<Box<dyn Firewall>>,
        notifier: Option<Box<dyn Notifier>>,
        own: OwnAddresses,
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
            startup: Startup::NotPolled,
            own,
            own_reported: BTreeSet::new(),
            safe_kept: BTreeSet::new(),
        };
        engine
            .state
            .ledger
            .fit(&Rules::of(&engine.cfg, engine.own.set()));
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
    /// Like every firewall check that the router answers, it is followed by
    /// the write of the safe list, if there is one (`keep_safe`), and the
    /// look-up of the own addresses in the address-list (`sweep_own`).
    pub fn startup_check(&mut self, host_now: u64) -> bool {
        let Some((result, safe_rule)) = self.check_firewall() else {
            return false;
        };
        let answered = match &result {
            Ok(found) => {
                crate::info!("firewall check ok: {}", found);
                match &safe_rule {
                    Some(Ok(found)) => crate::info!("safe list check ok: {}", found),
                    Some(Err(e)) => crate::error!("safe list check failed: {}", e),
                    None => {}
                }
                true
            }
            Err(e) => {
                crate::error!(
                    "firewall check failed: {} (bans will keep being retried)",
                    e
                );
                matches!(e, HealthError::NotEnforced(_))
            }
        };
        self.checked(result, safe_rule, answered, host_now);
        if answered {
            self.sweep_own(host_now);
        }
        answered
    }

    /// Logs the own addresses found at the start, and the look-ups that
    /// failed.
    pub fn startup_own(&self) {
        crate::info!("own addresses, never banned: {}", self.own.describe());
        let failures = self.own.failures();
        if !failures.is_empty() {
            crate::warn!(
                "own addresses: a look-up failed, it is tried again in every poll (a host \
                 name every {} min): {}",
                RESOLVE_EVERY / 60,
                failures.join("; ")
            );
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

    /// One health check of the firewall, with the rule of the safe list if
    /// there is one (`checked` gives the outcome to health).
    #[allow(clippy::type_complexity)]
    fn check_firewall(
        &self,
    ) -> Option<(Result<String, HealthError>, Option<Result<String, String>>)> {
        let checked = self.firewall.as_ref()?.check_with_safe_list();
        Some(match checked {
            Ok(checked) => (Ok(checked.found), checked.safe_rule),
            Err(e) => (Err(e), None),
        })
    }

    /// After a firewall check at `now`: when the router `answered` it, the
    /// write of the safe list (`keep_safe`); then the outcome goes to
    /// health. A write that finds the router unusable makes the check a
    /// failed one: the firewall problem stays open rather than passing at
    /// the check and failing at the write a moment later.
    fn checked(
        &mut self,
        result: Result<String, HealthError>,
        safe_rule: Option<Result<String, String>>,
        answered: bool,
        now: u64,
    ) {
        let unusable = if answered && !self.stopping() {
            self.keep_safe(now)
        } else {
            None
        };
        let result = match unusable {
            Some(e) => Err(HealthError::Unusable(e)),
            None => result,
        };
        self.health.firewall_checked(&result, now);
        if let Some(safe_rule) = &safe_rule {
            self.health.safe_rule_checked(safe_rule, now);
        }
    }

    /// The periodic firewall check, at most once per cycle, when health
    /// says it is due (see `Health::check_due`). When the router answered
    /// it, the own addresses are looked up in the address-list.
    fn periodic_check(&mut self, host_now: u64) {
        if !self.health.check_due(host_now) {
            return;
        }
        let Some((result, safe_rule)) = self.check_firewall() else {
            return;
        };
        let answered = match &result {
            Err(e) => {
                crate::warn!("firewall check failed: {}", e);
                matches!(e, HealthError::NotEnforced(_))
            }
            Ok(found) => {
                crate::debug!("firewall check ok: {}", found);
                match &safe_rule {
                    Some(Ok(found)) => crate::debug!("safe list check ok: {}", found),
                    Some(Err(e)) => crate::warn!("safe list check failed: {}", e),
                    None => {}
                }
                true
            }
        };
        self.checked(result, safe_rule, answered, host_now);
        if answered && !self.stopping() {
            self.sweep_own(host_now);
        }
    }

    /// With a safe list, keeps the own addresses toward the router in it
    /// for `SAFE_TIMEOUT` (ADR 0006): a look-up and a renewal or an add per
    /// address, at every firewall check the router answers. An address
    /// that is no longer an own address is left to expire. Without a safe
    /// list nothing is done and nothing is sent. A dry run sends nothing
    /// and says once per address what it would do. A refused write is the
    /// health problem `safe-list-refused`. A router that cannot be used
    /// ends the writes; its error is returned, for the firewall problem, as
    /// for a ban.
    fn keep_safe(&mut self, now: u64) -> Option<String> {
        let fw = self.firewall.as_ref()?;
        let list = fw.safe_list()?;
        // Only own addresses: built from the config and the host's sockets.
        let addresses = self.own.toward_router();
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
            return None;
        }
        if self.cfg.dry_run {
            for ip in addresses {
                if self.safe_kept.insert(ip) {
                    crate::info!(
                        "DRY RUN: would keep {} in the safe list {} for {}, renewed at every \
                         firewall check",
                        ip,
                        list,
                        timeout
                    );
                }
            }
            return None;
        }
        let mut refused: Option<(Ipv4Addr, String)> = None;
        for ip in addresses {
            if self.stopping() {
                return None;
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
                        return Some(error);
                    }
                    refused = Some((ip, error));
                }
            }
        }
        let write = match &refused {
            None => SafeWrite::Written,
            Some((ip, error)) => SafeWrite::Refused {
                ip: *ip,
                list: &list,
                error,
            },
        };
        self.health.safe_written(write, now);
        None
    }

    /// Asks the firewall whether an own address is in the address-list, one
    /// request per own address outside the reserved ranges, and removes
    /// each entry found: the only ban hik-f2b removes (ADR 0005). Each
    /// removal is a WARNING and a notification at once. In a dry run it is
    /// reported (once while it stays listed) and not removed. A removal
    /// that fails is an ERROR, a notification once while the address stays
    /// listed and the health problem `own-address-listed`, which only a
    /// look-up of every own address that finds none left ends.
    fn sweep_own(&mut self, now: u64) {
        let Some(fw) = &self.firewall else {
            return;
        };
        let addresses = self.own.to_ask();
        self.own_reported.retain(|ip| addresses.contains(ip));
        let list = fw.describe();
        let mut stuck: Option<(Ipv4Addr, String)> = None;
        for ip in addresses {
            if self.stop.load(Ordering::Relaxed) {
                return;
            }
            let ids = match fw.entries(ip) {
                Ok(ids) => ids,
                Err(e) => {
                    // Not every own address was asked: the problem stays as
                    // it is.
                    crate::warn!(
                        "cannot ask {} whether own address {} is listed: {}",
                        list,
                        ip,
                        e
                    );
                    return;
                }
            };
            if ids.is_empty() {
                self.own_reported.remove(&ip);
                continue;
            }
            if self.cfg.dry_run {
                if self.own_reported.insert(ip) {
                    crate::warn!(
                        "DRY RUN: {} is an own address of hik-f2b and is in {}: it would be \
                         removed",
                        ip,
                        list
                    );
                    self.outbox.queue(format!(
                        "\u{26a0}\u{fe0f} hik-f2b: {} is an own address of hik-f2b and is in {}. \
                         Dry run: it is not removed; remove it by hand.",
                        ip, list
                    ));
                }
                continue;
            }
            let removed = ids.iter().try_for_each(|id| fw.remove(ip, id));
            match removed {
                Ok(()) => {
                    self.own_reported.remove(&ip);
                    crate::warn!(
                        "{} is an own address of hik-f2b and was in {}: the entry is removed",
                        ip,
                        list
                    );
                    self.outbox.queue(format!(
                        "\u{26a0}\u{fe0f} hik-f2b: {} is an own address of hik-f2b and was in {}; \
                         the entry is removed. hik-f2b never bans its own addresses: it was added \
                         by hand, by another tool or by an earlier version.",
                        ip, list
                    ));
                }
                Err(e) => {
                    let error = e.to_string();
                    crate::error!(
                        "cannot remove own address {} from {}, will retry at the next firewall \
                         check: {}",
                        ip,
                        list,
                        error
                    );
                    if self.own_reported.insert(ip) {
                        self.outbox.queue(format!(
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
        let stuck = stuck.as_ref().map(|(ip, error)| OwnStuck {
            ip: *ip,
            list: &list,
            error,
        });
        self.health.own_swept(stuck, now);
    }

    /// Logs the health notices that are due and queues them for the chat
    /// (the outbox keeps nothing without a notifier).
    fn report_health(&mut self, host_now: u64) {
        let to_chat = self.cfg.telegram.as_ref().is_none_or(|t| t.health_alerts);
        for notice in self.health.due(host_now) {
            log_notice(&notice);
            if to_chat {
                self.outbox.queue(notice.text());
            }
        }
    }

    /// Problems that have been alerted and still persist, by key (for
    /// tests and diagnostics).
    pub fn alerted_problems(&self) -> Vec<String> {
        self.health.alerted()
    }

    /// One full pass at the current host time.
    fn cycle(&mut self) {
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
        self.startup.polled(host_now, self.grace());
        if !self.stopping() {
            self.own.refresh(host_now);
        }
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
        self.outbox.send(host_now, &self.stop);
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
            let rules = Rules::of(&self.cfg, self.own.set());
            register(&login, now, &rules, &mut self.state, report_once);
        }
    }

    /// Applies waiting bans. The firewall turning out to be unusable
    /// (unreachable, refusing our login or answering with an error) ends the
    /// attempts for this cycle.
    fn flush_pending(&mut self, now: u64) {
        let bantime = self.cfg.bantime;
        let due = self
            .state
            .ledger
            .due(&Rules::of(&self.cfg, self.own.set()), now);
        let mut end = BansEnded::Complete;
        for ip in due {
            if self.stopping() {
                end = BansEnded::Stopped;
                break;
            }
            let p = match self
                .state
                .ledger
                .next_ban(&Rules::of(&self.cfg, self.own.set()), ip)
            {
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
            // (attacker-chosen, up to `MAX_USER` characters) cannot reach. The
            // whole comment stays within 110 characters.
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
                        // attacker that keeps going cannot hide this. Right
                        // after the start that time may come from another
                        // `bantime` (see `Startup`).
                        let banned_at = self
                            .state
                            .ledger
                            .ban_began(&Rules::of(&self.cfg, self.own.set()), ip);
                        let recent = now.saturating_sub(banned_at.unwrap_or(0)) <= self.grace();
                        if !recent && !self.startup.running() {
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
                .outcome(&Rules::of(&self.cfg, self.own.set()), ip, now, outcome);
            if notify {
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
                self.outbox.queue(text);
            }
        }
        self.health
            .bans_ended(end, self.state.ledger.waiting(), now);
    }

    /// How long after a ban (and after the start) failed logins of a listed
    /// address may still come from before the ban: two polls and a minute.
    fn grace(&self) -> u64 {
        self.cfg.poll_interval.saturating_mul(2).saturating_add(60)
    }

    fn cleanup(&mut self, host_now: u64) {
        self.state
            .ledger
            .cleanup(&Rules::of(&self.cfg, self.own.set()), host_now);
    }

    /// Notifications waiting to be sent (for tests and diagnostics).
    pub fn queued_notifications(&self) -> usize {
        self.outbox.waiting()
    }

    /// What the engine remembers: the ledger and the read cursors, as the
    /// state file holds them (for tests and diagnostics).
    pub fn state(&self) -> &State {
        &self.state
    }

    /// The NVR log readers, one per NVR of the config, in its order (for
    /// tests and diagnostics).
    pub fn readers(&self) -> &[LogReader] {
        &self.readers
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

#[cfg(test)]
mod tests {
    use super::Startup;

    const T0: u64 = 1_768_000_000;
    const GRACE: u64 = 120;

    fn after(polls: &[u64]) -> Startup {
        let mut s = Startup::NotPolled;
        for t in polls {
            s.polled(*t, GRACE);
        }
        s
    }

    #[test]
    fn the_period_runs_from_the_first_poll_for_one_grace_period() {
        assert!(!Startup::NotPolled.running());
        assert_eq!(after(&[T0]), Startup::Since(T0));
        assert!(after(&[T0, T0 + 30, T0 + GRACE]).running());
        assert_eq!(after(&[T0, T0 + GRACE + 1]), Startup::Over);
        // a long pause between two polls ends it as well
        assert_eq!(after(&[T0, T0 + 86400]), Startup::Over);
    }

    #[test]
    fn the_period_never_comes_back() {
        assert_eq!(after(&[T0, T0 + GRACE + 1, T0 + 30]), Startup::Over);
        assert_eq!(after(&[T0, T0 + GRACE + 1, T0]), Startup::Over);
    }

    #[test]
    fn a_host_clock_that_goes_back_ends_the_period() {
        // counted from the time the clock went back to, the period would
        // last until T0 - 3600 + GRACE: longer than one grace period
        assert_eq!(after(&[T0, T0 + 30, T0 - 3600]), Startup::Over);
        assert_eq!(after(&[T0, T0 - 1]), Startup::Over);
        assert!(!after(&[T0, T0 - 3600, T0 - 3600 + 30]).running());
    }
}
