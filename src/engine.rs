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
//! firewall check round and each ban attempt went, how the ban loop ended
//! and when the poll ends; that module decides which health check this
//! opens or ends and when it is worth an alert.
//!
//! Notifications (about bans and from health) are rendered here and handed
//! to the outbox (`outbox.rs`) as texts; at the end of the poll the outbox
//! sends what it can.
//!
//! The own addresses (`own.rs`) are looked up again at the start of every
//! poll (a host name at most every `names::RESOLVE_EVERY`) and given to the
//! ledger with the rules. The firewall check, at the start and then when
//! health says it is due, is a round of its own (`round.rs`): it asks the
//! router whether an own address is in the address-list and removes it if
//! it is, the only ban hik-f2b ever removes (ADR 0005), and with a safe
//! list it keeps the own address toward the router in it (ADR 0006). The
//! engine only says when a round runs, and passes what it came to on to
//! health and the outbox.
//!
//! The host names of `ignoreip` (`ignored.rs`) are looked up again at the
//! start of every poll too (each at most every `names::RESOLVE_EVERY`), and
//! the addresses they resolve to are given to the ledger with the rules.
//! They are not own addresses: no ban is removed for them and none goes to
//! the safe list (ADR 0007).

use crate::action::{render, BanError, BanInfo, Firewall, Notifier};
use crate::config::{Config, DEFAULT_MESSAGE};
use crate::country::{self, Code};
use crate::health::{BanAttempt, BansEnded, Health, Kind, Notice, NvrRead};
use crate::ignored::IgnoredNames;
use crate::ledger::{Outcome, Refusals, Rules, Turn, MAX_REFUSALS_PER_POLL, MAX_USER};
use crate::names::RESOLVE_EVERY;
use crate::nvr::{Nvr, NvrError};
use crate::outbox::Outbox;
use crate::own::OwnAddresses;
use crate::reader::{LogReader, Login, Logins, Poll};
use crate::round::{Round, When};
use crate::state::State;
use crate::util::{self, host_i64};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    /// The host names of `ignoreip`: what they resolve to is never banned.
    ignored: IgnoredNames,
    /// The firewall check round, with what it remembers between checks.
    round: Round,
    /// Which waiting bans the firewall refused, and in which order: the
    /// order in which they are tried (in memory only).
    refusals: Refusals,
    /// Whether the last ban loop that ended on its own left waiting bans
    /// for the next polls after `MAX_REFUSALS_PER_POLL` refusals: that is
    /// logged when it starts.
    deferring: bool,
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
    /// configuration asks for), the own addresses of `cfg` and the host
    /// names of its `ignoreip`. It sets up a client per NVR of `cfg`.
    pub fn new(
        cfg: Config,
        state: State,
        firewall: Option<Box<dyn Firewall>>,
        notifier: Option<Box<dyn Notifier>>,
        own: OwnAddresses,
        ignored: IgnoredNames,
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
            ignored,
            round: Round::new(),
            refusals: Refusals::default(),
            deferring: false,
        };
        engine.state.ledger.fit(&Rules::of(
            &engine.cfg,
            engine.own.set(),
            engine.ignored.addresses(),
        ));
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

    /// The start of the service, at host time `host_now`, before the first
    /// cycle. In this order: logs the own addresses (`startup_own`), what
    /// the host names of `ignoreip` resolve to (`startup_names`) and the
    /// country database (`startup_country`), runs the first firewall check
    /// round (`startup_check`) and, only when the router answered it, logs
    /// the number of entries in the address-list. An engine that was built
    /// but not started works all the same, except that its first firewall
    /// check is the periodic one, in its first cycle.
    pub fn start(&mut self, host_now: u64) {
        self.startup_own();
        self.startup_names();
        self.startup_country();
        // Also in a dry run: that is when the setup is being checked. The size
        // of the address-list is asked only of a router that answered it, so an
        // unreachable one costs one timeout at startup, not two.
        let answered = self.startup_check(host_now);
        if answered {
            let list = self.cfg.mikrotik.as_ref().map(|m| &m.address_list);
            if let (Some(list), Some(count)) = (list, self.count_listed()) {
                match count {
                    Ok(n) => crate::info!("MikroTik address-list {} has {} entries", list, n),
                    Err(e) => {
                        crate::warn!("cannot count the entries of address-list {}: {}", list, e)
                    }
                }
            }
        }
    }

    /// Runs the firewall check round once at startup (`round.rs`); the
    /// first periodic check follows `health::HEALTH_CHECK_INTERVAL` later.
    /// Returns whether the firewall answered (so that more can be asked of
    /// it without waiting for a second timeout).
    fn startup_check(&mut self, host_now: u64) -> bool {
        self.firewall_round(When::Start, host_now).unwrap_or(false)
    }

    /// The number of entries in the address-list, shown at startup;
    /// `None` without a firewall.
    fn count_listed(&self) -> Option<Result<usize, String>> {
        self.firewall.as_ref().map(|fw| fw.count())
    }

    /// Logs the own addresses found at the start, and the look-ups that
    /// failed.
    fn startup_own(&self) {
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

    /// Logs what the host names of `ignoreip` resolve to at the start, and
    /// the names that do not resolve; nothing without a name.
    fn startup_names(&self) {
        self.ignored.log_start();
    }

    /// Logs which country database is configured, or why it cannot be
    /// read. Either way the service runs; without the file bans simply
    /// carry no country.
    fn startup_country(&mut self) {
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

    /// The periodic firewall check round, at most once per cycle, when
    /// health says it is due (see `Health::check_due`).
    fn periodic_check(&mut self, host_now: u64) {
        if !self.health.check_due(host_now) {
            return;
        }
        self.firewall_round(When::Periodic, host_now);
    }

    /// A firewall check round at `now`, if there is a firewall: what it
    /// came to goes to health, and its notifications to the outbox.
    /// Returns whether the router answered.
    fn firewall_round(&mut self, when: When, now: u64) -> Option<bool> {
        let fw = self.firewall.as_deref()?;
        let ended = self.round.run(
            fw,
            when,
            &self.own.toward_router(),
            &self.own.to_ask(),
            self.cfg.dry_run,
            &self.stop,
        );
        self.health.round_ended(&ended, now);
        for text in ended.notifications {
            self.outbox.queue(text);
        }
        Some(ended.answered)
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
            self.ignored.refresh(host_now);
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
        // A stop that comes while the last notifications are sent, or
        // after, skips nothing: then the line below would not be true.
        let stopped = self.stopping();
        let held = self.outbox.send(host_now, &self.stop);
        self.cleanup(host_now);
        if stopped || held {
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
            let rules = Rules::of(&self.cfg, self.own.set(), self.ignored.addresses());
            register(&login, now, &rules, &mut self.state, report_once);
        }
    }

    /// Applies waiting bans. The firewall turning out to be unusable
    /// (unreachable, refusing our login or answering with an error) ends the
    /// attempts for this cycle. So do `MAX_REFUSALS_PER_POLL` bans that the
    /// firewall refused: each costs two requests (see `Mikrotik::ban`), and
    /// a firewall that refuses one ban mostly refuses all. The bans are
    /// tried in the order `Refusals` gives, so that the rest are tried in
    /// the next polls.
    fn flush_pending(&mut self, now: u64) {
        let bantime = self.cfg.bantime;
        let due = self.state.ledger.due(
            &Rules::of(&self.cfg, self.own.set(), self.ignored.addresses()),
            now,
        );
        let due = self.refusals.order(due);
        let mut end = BansEnded::Complete;
        let mut refused = 0;
        let mut deferred = false;
        for ip in due {
            if self.stopping() {
                end = BansEnded::Stopped;
                break;
            }
            if refused >= MAX_REFUSALS_PER_POLL {
                deferred = true;
                break;
            }
            let p = match self.state.ledger.next_ban(
                &Rules::of(&self.cfg, self.own.set(), self.ignored.addresses()),
                ip,
            ) {
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
                        self.refusals.refused(ip);
                        refused += 1;
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
                        let banned_at = self.state.ledger.ban_began(
                            &Rules::of(&self.cfg, self.own.set(), self.ignored.addresses()),
                            ip,
                        );
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
            self.state.ledger.outcome(
                &Rules::of(&self.cfg, self.own.set(), self.ignored.addresses()),
                ip,
                now,
                outcome,
            );
            if outcome != Outcome::NotApplied {
                self.refusals.forget(ip);
            }
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
        if end != BansEnded::Stopped {
            if deferred && !self.deferring {
                crate::warn!(
                    "the firewall refused {} bans in this poll: the other waiting bans are left \
                     for the next polls, which try the bans not refused yet first and the others \
                     in turn",
                    MAX_REFUSALS_PER_POLL
                );
            }
            self.deferring = deferred;
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
        self.state.ledger.cleanup(
            &Rules::of(&self.cfg, self.own.set(), self.ignored.addresses()),
            host_now,
        );
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
