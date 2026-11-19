#![forbid(unsafe_code)]

use hik_f2b::action::{BanTime, Firewall, Notifier};
use hik_f2b::config::{self, Config};
use hik_f2b::engine::Engine;
use hik_f2b::health::Status;
use hik_f2b::mikrotik::Mikrotik;
use hik_f2b::state::State;
use hik_f2b::telegram::Telegram;
use hik_f2b::{error, info, util, warn};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const USAGE: &str = "hik-f2b - ban Hikvision NVR brute-forcers on a MikroTik router
(or, without a [mikrotik] section, only report them)

usage: hik-f2b [options]

  -c, --config PATH   config file (default /etc/hik-f2b/hik-f2b.ini)
      --once          run a single poll cycle and exit
      --dry-run       log bans instead of applying them
      --dump          print recent NVR log entries and exit
      --hours N       how far back --dump looks (default 24)
      --raw           with --dump: also print the raw XML
      --test-ban IP   add IP to the address-list for 60 s and exit
      --test-notify   send a test Telegram message and exit
      --check         check every NVR, the firewall and its drop rule once,
                      print the results and exit (non-zero if any failed)
  -v, --verbose       more logging
      --version       print the version and exit
  -h, --help          this text
";

#[derive(Default)]
struct Args {
    config: Option<PathBuf>,
    once: bool,
    dry_run: bool,
    dump: bool,
    hours: Option<i64>,
    raw: bool,
    test_ban: Option<Ipv4Addr>,
    test_notify: bool,
    check: bool,
    verbose: bool,
}

fn parse_args() -> Result<Option<Args>, String> {
    let mut args = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = |name: &str| it.next().ok_or_else(|| format!("{} needs a value", name));
        match arg.as_str() {
            "-c" | "--config" => args.config = Some(PathBuf::from(value("--config")?)),
            "--once" => args.once = true,
            "--dry-run" => args.dry_run = true,
            "--dump" => args.dump = true,
            "--raw" => args.raw = true,
            "--hours" => {
                args.hours = Some(
                    value("--hours")?
                        .parse::<i64>()
                        .ok()
                        .filter(|h| (1..=24 * 365).contains(h))
                        .ok_or_else(|| "--hours must be a positive number".to_string())?,
                )
            }
            "--test-ban" => {
                args.test_ban = Some(
                    value("--test-ban")?
                        .parse::<Ipv4Addr>()
                        .map_err(|_| "--test-ban needs an IPv4 address".to_string())?,
                )
            }
            "--test-notify" => args.test_notify = true,
            "--check" => args.check = true,
            "-v" | "--verbose" => args.verbose = true,
            "--version" => {
                println!("hik-f2b {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            "-h" | "--help" => {
                print!("{}", USAGE);
                return Ok(None);
            }
            other => return Err(format!("unknown option {}", other)),
        }
    }
    Ok(Some(args))
}

/// Shows what the NVRs return, to check field names and `log_filter`.
fn dump(engine: &mut Engine, hours: i64, raw: bool) {
    let meta_id = engine.cfg.meta_id.clone();
    for nvr in engine.nvrs.iter_mut() {
        println!("=== {} ({})", nvr.name, nvr.url);
        let mut sink = Vec::new();
        let result = nvr.now().and_then(|now| {
            println!("device time: {}", util::fmt_ts(now));
            let sink = if raw { Some(&mut sink) } else { None };
            nvr.search(now - hours * 3600, now + 86400, &meta_id, sink)
        });
        let search = match result {
            Ok(search) => search,
            Err(e) => {
                println!("ERROR: {}", e);
                continue;
            }
        };
        for chunk in &sink {
            println!("{}", util::terminal_safe(chunk));
        }
        println!(
            "{} entries with metaId {} in the last {} h",
            search.events.len(),
            meta_id,
            hours
        );
        if search.skipped > 0 {
            println!(
                "{} more could not be parsed; AMBIG = a user, address, time or type field \
                 appears twice (never counted)",
                search.skipped
            );
        }
        let flagged = search
            .events
            .iter()
            .map(|ev| (false, ev))
            .chain(search.ambiguous.iter().map(|ev| (true, ev)));
        for (ambiguous, ev) in flagged {
            println!(
                "{}  {}  ip={:<15} user={:<18} {}",
                if ambiguous {
                    "AMBIG"
                } else if engine.cfg.log_filter.is_match(&ev.meta) {
                    "MATCH"
                } else {
                    "     "
                },
                ev.ts.map(util::fmt_ts).unwrap_or_else(|| "?".to_string()),
                ev.ip
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                format!("{:?}", util::sanitize(&ev.user, 32)),
                util::sanitize(&ev.meta, 100)
            );
        }
    }
}

fn run() -> Result<(), String> {
    let Some(args) = parse_args()? else {
        return Ok(());
    };
    util::set_verbose(args.verbose);
    let path = args
        .config
        .unwrap_or_else(|| PathBuf::from("/etc/hik-f2b/hik-f2b.ini"));
    let mut cfg = Config::load(&path)?;
    cfg.dry_run = cfg.dry_run || args.dry_run;
    if cfg.inline_secrets && config::world_readable(&path) {
        warn!(
            "{} holds passwords and is readable by all users; move them to files with password_file",
            path.display()
        );
    }
    let state_file = cfg.state_file.clone();
    let poll_interval = cfg.poll_interval;
    let daemon = !(args.dump || args.test_ban.is_some() || args.test_notify || args.check);
    let state = if daemon {
        State::load(&state_file)
    } else {
        State::default()
    };

    let mikrotik = match &cfg.mikrotik {
        Some(m) => Some(Mikrotik::new(m)?),
        None => None,
    };
    let telegram = match &cfg.telegram {
        Some(t) => Some(Telegram::new(t)?),
        None => None,
    };
    if daemon {
        info!(
            "hik-f2b {} started: {} NVR(s), maxretry={} findtime={}s bantime={} telegram={}{}",
            env!("CARGO_PKG_VERSION"),
            cfg.nvrs.len(),
            cfg.maxretry,
            cfg.findtime,
            cfg.bantime,
            if telegram.is_some() { "on" } else { "off" },
            if cfg.dry_run { " DRY RUN" } else { "" }
        );
        match (&mikrotik, cfg.dry_run) {
            (Some(m), false) => info!("mode: ban on MikroTik, address-list {}", m.list),
            (Some(m), true) => info!(
                "mode: DRY RUN, bans on MikroTik address-list {} are only logged",
                m.list
            ),
            (None, _) => info!(
                "mode: notify-only (no [mikrotik] section): addresses that reach maxretry are \
                 reported, nothing is banned"
            ),
        }
        if mikrotik.is_none() && telegram.is_none() {
            warn!(
                "neither [mikrotik] nor [telegram] is configured: detections are only written \
                 to this log"
            );
        }
        // MikroTik-specific, so done before the client is handed to the
        // engine as a plain firewall. A failure is reported by the health
        // check below.
        if let Some(m) = &mikrotik {
            if let Ok(n) = m.count() {
                info!("MikroTik address-list {} has {} entries", m.list, n);
            }
        }
    }
    let firewall = mikrotik.map(|m| Box::new(m) as Box<dyn Firewall>);
    let notifier = telegram.map(|t| Box::new(t) as Box<dyn Notifier>);
    let mut engine = Engine::with_parts(cfg, state, firewall, notifier)?;

    if args.check {
        let lines = engine.check_all();
        for line in &lines {
            println!("{}", util::terminal_safe(&line.to_string()));
        }
        let failed = lines
            .iter()
            .filter(|line| line.status == Status::Failed)
            .count();
        if failed > 0 {
            return Err(format!("{} check(s) failed", failed));
        }
        return Ok(());
    }
    if args.dump {
        dump(&mut engine, args.hours.unwrap_or(24), args.raw);
        return Ok(());
    }
    if let Some(ip) = args.test_ban {
        let firewall = engine.firewall.as_ref().ok_or_else(|| {
            "--test-ban needs a firewall, but there is no [mikrotik] section in the config"
                .to_string()
        })?;
        let added = firewall
            .ban(ip, BanTime::Seconds(60), "hik-f2b test")
            .map_err(|e| e.to_string())?;
        println!(
            "ok: {} {} {} (60 s)",
            ip,
            if added { "added to" } else { "is already in" },
            firewall.describe()
        );
        return Ok(());
    }
    if args.test_notify {
        let notifier = engine
            .notifier
            .as_ref()
            .ok_or_else(|| "no [telegram] section in the config".to_string())?;
        notifier.send("hik-f2b test message: notifications work.")?;
        println!("ok: test message sent");
        return Ok(());
    }

    let stop = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register(signal, Arc::clone(&stop))
            .map_err(|e| format!("cannot install signal handler: {}", e))?;
    }

    // Also in a dry run: that is when the setup is being checked.
    engine.startup_check(util::unix_now());

    let mut saved = engine.state.serialize();
    while !stop.load(Ordering::Relaxed) {
        engine.cycle();
        let current = engine.state.serialize();
        if current != saved {
            match engine.state.save(&state_file) {
                Ok(()) => saved = current,
                Err(e) => error!(
                    "cannot save state to {}: {}",
                    state_file.display(),
                    e.kind()
                ),
            }
        }
        if args.once {
            break;
        }
        let deadline = Instant::now() + Duration::from_secs(poll_interval);
        while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    info!("stopped");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hik-f2b: {}", util::sanitize(&e, 300));
            ExitCode::FAILURE
        }
    }
}
