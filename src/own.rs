//! Own addresses: the IPv4 addresses of this host and of its devices, which
//! are never banned.
//!
//! For each device of the config (the router and every NVR) the set holds
//! the device's own addresses (the host of its URL, resolved when it is a
//! name) and, for each of them, the local address the operating system
//! would send from to reach it. They are found at run time, never written
//! in the config: at startup and again in every poll (`OwnAddresses::refresh`),
//! because an address can change (DHCP, a VPN that reconnects). The local
//! address is asked for in every poll (the kernel answers at once); a host
//! name is resolved at startup and then at most every `names::RESOLVE_EVERY`
//! (`names::Names`), and an IPv4 address in a URL needs no look-up. When a
//! look-up fails, what was last found for that device stays.
//!
//! The answers come through `Source`: the operating system (`System`), or
//! fixed answers (`Fixed`) for tests and the simulation, whose devices all
//! live on loopback, which is never banned anyway.
//!
//! The set is built from the config and from what the host's own sockets
//! and resolver answer, and from nothing else: see `OwnAddresses::new`. The
//! ban ledger is told the set and never looks anything up (`ledger::Rules`).

use crate::config::Config;
use crate::ledger::never_ban;
use crate::names::Names;
use crate::util;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};

/// Longest reason kept for a failed look-up.
const MAX_REASON: usize = 200;

/// Where the answers about own addresses come from.
pub trait Source {
    /// The IPv4 addresses of `host` (a name or an IPv4 address, as the URL
    /// gives it), for connections to `port`. A host name of `ignoreip`
    /// (`ignored.rs`) is resolved with port 0: no connection goes to it.
    fn resolve(&mut self, host: &str, port: u16) -> Result<Vec<Ipv4Addr>, String>;
    /// The local address this host would send from to reach `peer` at
    /// `port`.
    fn local_toward(&mut self, peer: Ipv4Addr, port: u16) -> Result<Ipv4Addr, String>;
}

/// The operating system: its resolver, and a UDP socket connected to the
/// device, whose local address the kernel picks by its routes. Connecting
/// a UDP socket sends no packet.
pub struct System;

impl Source for System {
    fn resolve(&mut self, host: &str, port: u16) -> Result<Vec<Ipv4Addr>, String> {
        let addresses = (host, port)
            .to_socket_addrs()
            .map_err(|e| format!("cannot resolve {}: {}", host, e))?;
        let mut out: Vec<Ipv4Addr> = addresses
            .filter_map(|a| match a {
                SocketAddr::V4(a) => Some(*a.ip()),
                SocketAddr::V6(_) => None,
            })
            .collect();
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    fn local_toward(&mut self, peer: Ipv4Addr, port: u16) -> Result<Ipv4Addr, String> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .map_err(|e| format!("cannot open a socket: {}", e))?;
        socket
            .connect((peer, port))
            .map_err(|e| format!("no route to {}: {}", peer, e))?;
        match socket.local_addr() {
            Ok(SocketAddr::V4(a)) if !a.ip().is_unspecified() => Ok(*a.ip()),
            Ok(other) => Err(format!("no local IPv4 address toward {} ({})", peer, other)),
            Err(e) => Err(format!("no local address toward {}: {}", peer, e)),
        }
    }
}

/// Fixed answers, for tests and the simulation. Clones share the answers,
/// so a test can change them while an engine uses another clone.
#[derive(Clone)]
pub struct Fixed(Arc<Mutex<Answers>>);

struct Answers {
    /// The answer to every `local_toward`.
    local: Result<Ipv4Addr, String>,
    /// The answers for host names; an IPv4 address resolves to itself.
    names: BTreeMap<String, Result<Vec<Ipv4Addr>, String>>,
    /// How many times `resolve` was called.
    resolved: usize,
}

impl Fixed {
    /// Every device is reached from `local`.
    pub fn new(local: Ipv4Addr) -> Fixed {
        Fixed(Arc::new(Mutex::new(Answers {
            local: Ok(local),
            names: BTreeMap::new(),
            resolved: 0,
        })))
    }

    fn answers(&self) -> std::sync::MutexGuard<'_, Answers> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// From now on every device is reached from this address, or the
    /// look-up fails with this reason.
    pub fn set_local(&self, local: Result<Ipv4Addr, String>) {
        self.answers().local = local;
    }

    /// From now on `name` resolves to these addresses, or fails with this
    /// reason.
    pub fn set_name(&self, name: &str, answer: Result<Vec<Ipv4Addr>, String>) {
        self.answers().names.insert(name.to_string(), answer);
    }

    /// How many times a host was resolved through these answers.
    pub fn resolved(&self) -> usize {
        self.answers().resolved
    }
}

impl Source for Fixed {
    fn resolve(&mut self, host: &str, _port: u16) -> Result<Vec<Ipv4Addr>, String> {
        let mut answers = self.answers();
        answers.resolved += 1;
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Ok(vec![ip]);
        }
        match answers.names.get(host) {
            Some(answer) => answer.clone(),
            None => Err(format!("cannot resolve {}: no such name", host)),
        }
    }

    fn local_toward(&mut self, _peer: Ipv4Addr, _port: u16) -> Result<Ipv4Addr, String> {
        self.answers().local.clone()
    }
}

/// One device of the config: its name in log lines (`router`, or the NVR's
/// name) and the host and port of its URL.
#[derive(Clone, Debug, PartialEq)]
struct Device {
    name: String,
    host: String,
    port: u16,
}

impl Device {
    /// The device behind `url` (`http(s)://host[:port]`, as the config
    /// checked it).
    fn of(name: &str, url: &str) -> Device {
        let (default_port, rest) = match url.strip_prefix("https://") {
            Some(rest) => (443, rest),
            None => (80, url.strip_prefix("http://").unwrap_or(url)),
        };
        // `[v6]:port` keeps its brackets out of the host; the resolver
        // finds no IPv4 address for it.
        let (host, port) = match rest.strip_prefix('[') {
            Some(v6) => match v6.split_once(']') {
                Some((host, port)) => (host, port),
                None => (v6, ""),
            },
            None => rest.split_once(':').map_or((rest, ""), |(h, p)| (h, p)),
        };
        let port = port
            .trim_start_matches(':')
            .parse::<u16>()
            .unwrap_or(default_port);
        Device {
            name: name.to_string(),
            host: host.to_string(),
            port,
        }
    }
}

/// What was last found for one device: its addresses, and for each the
/// local address it is reached from (if that was ever found).
#[derive(Clone, Debug, Default, PartialEq)]
struct Found {
    addresses: Vec<Ipv4Addr>,
    local: BTreeMap<Ipv4Addr, Ipv4Addr>,
}

/// The own addresses: what was last found for each device of the config,
/// and why a look-up failed, if it did.
pub struct OwnAddresses {
    /// The devices of the config: the router first, if there is one.
    devices: Vec<Device>,
    /// Whether `devices` starts with the router.
    router: bool,
    source: Box<dyn Source>,
    /// The host names of the devices, resolved now and then.
    names: Names,
    found: Vec<Found>,
    /// Why the last look-up for each device failed (`None`: it worked).
    failures: Vec<Option<String>>,
    set: BTreeSet<Ipv4Addr>,
}

impl OwnAddresses {
    /// The own addresses of the devices in `cfg` (the router, then the
    /// NVRs, in the order of the config), looked up once through `source`.
    /// Nothing is logged.
    ///
    /// This is where the set is built, and its inputs are all it is built
    /// from: the URLs of the config and the answers of `source`. Nothing
    /// read from an NVR log can reach it, so a forged log entry cannot make
    /// an address exempt; no method takes an address to add.
    pub fn new(cfg: &Config, source: Box<dyn Source>) -> OwnAddresses {
        let mut devices = Vec::new();
        if let Some(m) = &cfg.mikrotik {
            devices.push(Device::of("router", &m.url));
        }
        for nvr in &cfg.nvrs {
            devices.push(Device::of(&nvr.name, &nvr.url));
        }
        let mut own = OwnAddresses {
            found: vec![Found::default(); devices.len()],
            failures: vec![None; devices.len()],
            router: cfg.mikrotik.is_some(),
            devices,
            source,
            names: Names::new(),
            set: BTreeSet::new(),
        };
        own.look_up(None);
        own
    }

    /// Looks every device up again at host time `now`: the local addresses
    /// at once, a host name only when its answer is `names::RESOLVE_EVERY`
    /// old. Logs, as INFO, a change of the set, and a failed look-up
    /// whenever its reason changes (WARNING) and when it works again (INFO).
    pub fn refresh(&mut self, now: u64) {
        let before = self.set.clone();
        let failures = self.failures.clone();
        self.look_up(Some(now));
        for (i, (was, now)) in failures.iter().zip(&self.failures).enumerate() {
            let name = &self.devices[i].name;
            match (was, now) {
                (_, Some(e)) if was.as_ref() != Some(e) => crate::warn!(
                    "own addresses: the look-up for {} failed, its last known addresses stay: {}",
                    name,
                    e
                ),
                (Some(_), None) => {
                    crate::info!("own addresses: the look-up for {} works again", name)
                }
                _ => {}
            }
        }
        if self.set != before {
            let list = |s: Vec<&Ipv4Addr>| {
                if s.is_empty() {
                    "none".to_string()
                } else {
                    s.iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            };
            crate::info!(
                "own addresses changed: added {}, removed {}; now {}",
                list(self.set.difference(&before).collect()),
                list(before.difference(&self.set).collect()),
                self.describe()
            );
        }
    }

    /// One look-up of every device at host time `now` (`None` at startup).
    fn look_up(&mut self, now: Option<u64>) {
        for (i, device) in self.devices.iter().enumerate() {
            let found = &mut self.found[i];
            let mut errors = Vec::new();
            let source = &mut self.source;
            let (addresses, error) = self
                .names
                .lookup(&device.host, now, |host| source.resolve(host, device.port));
            if !addresses.is_empty() {
                found.addresses = addresses;
            }
            errors.extend(error);
            let addresses = found.addresses.clone();
            found.local.retain(|peer, _| addresses.contains(peer));
            for peer in addresses {
                match self.source.local_toward(peer, device.port) {
                    Ok(local) => {
                        found.local.insert(peer, local);
                    }
                    Err(e) => errors.push(e),
                }
            }
            self.failures[i] = if errors.is_empty() {
                None
            } else {
                Some(util::printable(&errors.join("; "), MAX_REASON))
            };
        }
        self.set = self
            .found
            .iter()
            .flat_map(|f| f.addresses.iter().chain(f.local.values()))
            .copied()
            .collect();
    }

    /// The own addresses, as last found.
    pub fn set(&self) -> &BTreeSet<Ipv4Addr> {
        &self.set
    }

    /// The own addresses that are worth asking the router about: those
    /// outside the ranges that are never banned anyway (loopback, say).
    pub fn to_ask(&self) -> Vec<Ipv4Addr> {
        self.set
            .iter()
            .copied()
            .filter(|ip| !never_ban(*ip))
            .collect()
    }

    /// The local addresses this host reaches the router from, as last
    /// found, outside the ranges that are never banned anyway: what the
    /// safe list holds. Part of the set, so built only from the config and
    /// the host's own sockets: nothing read from an NVR log reaches it.
    pub fn toward_router(&self) -> Vec<Ipv4Addr> {
        if !self.router {
            return Vec::new();
        }
        let local: BTreeSet<Ipv4Addr> = self.found[0].local.values().copied().collect();
        local.into_iter().filter(|ip| !never_ban(*ip)).collect()
    }

    /// Why the last look-ups failed, by device (empty when all worked).
    pub fn failures(&self) -> Vec<String> {
        self.devices
            .iter()
            .zip(&self.failures)
            .filter_map(|(d, e)| e.as_ref().map(|e| format!("{}: {}", d.name, e)))
            .collect()
    }

    /// What was found, by device: `router 192.0.2.1 from 192.0.2.200, nvr1
    /// 192.0.2.5 from 192.0.2.200`; a device found nothing for yet is
    /// `nvr1 not found`.
    pub fn describe(&self) -> String {
        let parts: Vec<String> = self
            .devices
            .iter()
            .zip(&self.found)
            .map(|(device, found)| {
                if found.addresses.is_empty() {
                    return format!("{} not found", device.name);
                }
                let each: Vec<String> = found
                    .addresses
                    .iter()
                    .map(|peer| match found.local.get(peer) {
                        Some(local) => format!("{} from {}", peer, local),
                        None => peer.to_string(),
                    })
                    .collect();
                format!("{} {}", device.name, each.join(" and "))
            })
            .collect();
        if parts.is_empty() {
            "none (no device in the config)".to_string()
        } else {
            parts.join(", ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::RESOLVE_EVERY;
    use crate::util::{capture_log, captured_log};

    const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 200);
    const T0: u64 = 1_768_000_000;

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    fn config(router: Option<&str>, nvrs: &[(&str, &str)]) -> Config {
        let mut ini = "[general]\nstate_file = /tmp/hik-f2b-own-test\n".to_string();
        if let Some(url) = router {
            ini.push_str(&format!(
                "[mikrotik]\nurl = {}\nuser = f2b\npassword = x\nca_file = public\n",
                url
            ));
        }
        for (name, url) in nvrs {
            ini.push_str(&format!(
                "[nvr:{}]\nurl = {}\nuser = f2b\npassword = x\n",
                name, url
            ));
        }
        Config::parse(&ini).unwrap()
    }

    fn set(own: &OwnAddresses) -> Vec<String> {
        own.set().iter().map(|ip| ip.to_string()).collect()
    }

    #[test]
    fn the_devices_and_the_local_address_toward_each() {
        let fixed = Fixed::new(LOCAL);
        fixed.set_name("nvr.example.net", Ok(vec![ip("198.51.100.5")]));
        let cfg = config(
            Some("https://192.0.2.1"),
            &[
                ("nvr1", "http://198.51.100.4:8080"),
                ("nvr2", "https://nvr.example.net"),
            ],
        );
        let own = OwnAddresses::new(&cfg, Box::new(fixed));
        assert_eq!(
            set(&own),
            ["192.0.2.1", "192.0.2.200", "198.51.100.4", "198.51.100.5"]
        );
        assert_eq!(
            own.describe(),
            "router 192.0.2.1 from 192.0.2.200, nvr1 198.51.100.4 from 192.0.2.200, nvr2 \
             198.51.100.5 from 192.0.2.200"
        );
        assert!(own.failures().is_empty());
    }

    #[test]
    fn notify_only_mode_has_only_the_nvrs() {
        let cfg = config(None, &[("nvr1", "http://198.51.100.4")]);
        let own = OwnAddresses::new(&cfg, Box::new(Fixed::new(LOCAL)));
        assert_eq!(set(&own), ["192.0.2.200", "198.51.100.4"]);
        assert_eq!(own.describe(), "nvr1 198.51.100.4 from 192.0.2.200");
    }

    #[test]
    fn the_address_toward_the_router_is_the_local_one() {
        let fixed = Fixed::new(LOCAL);
        let cfg = config(
            Some("https://192.0.2.1"),
            &[("nvr1", "http://198.51.100.4")],
        );
        let mut own = OwnAddresses::new(&cfg, Box::new(fixed.clone()));
        assert_eq!(own.toward_router(), vec![LOCAL]);
        // it follows the host
        fixed.set_local(Ok(ip("192.0.2.201")));
        own.refresh(T0);
        assert_eq!(own.toward_router(), vec![ip("192.0.2.201")]);
        // a failed look-up keeps it
        fixed.set_local(Err("no route".to_string()));
        own.refresh(T0 + 30);
        assert_eq!(own.toward_router(), vec![ip("192.0.2.201")]);
        // none without a router, none on loopback, none never found
        let cfg = config(None, &[("nvr1", "http://198.51.100.4")]);
        assert!(OwnAddresses::new(&cfg, Box::new(Fixed::new(LOCAL)))
            .toward_router()
            .is_empty());
        let cfg = config(
            Some("http://127.0.0.1:8728"),
            &[("nvr1", "http://198.51.100.4")],
        );
        assert!(
            OwnAddresses::new(&cfg, Box::new(Fixed::new(Ipv4Addr::LOCALHOST)))
                .toward_router()
                .is_empty()
        );
        let cfg = config(
            Some("https://router.example.net"),
            &[("nvr1", "http://198.51.100.4")],
        );
        assert!(OwnAddresses::new(&cfg, Box::new(Fixed::new(LOCAL)))
            .toward_router()
            .is_empty());
    }

    #[test]
    fn reserved_ranges_need_no_question_to_the_router() {
        let cfg = config(
            Some("http://127.0.0.1:8728"),
            &[("nvr1", "http://198.51.100.4")],
        );
        let fixed = Fixed::new(Ipv4Addr::LOCALHOST);
        let own = OwnAddresses::new(&cfg, Box::new(fixed.clone()));
        assert_eq!(set(&own), ["127.0.0.1", "198.51.100.4"]);
        assert_eq!(own.to_ask(), vec![ip("198.51.100.4")]);
    }

    #[test]
    fn a_change_is_one_info_line() {
        let fixed = Fixed::new(LOCAL);
        let cfg = config(Some("https://192.0.2.1"), &[("nvr1", "http://192.0.2.5")]);
        capture_log();
        let mut own = OwnAddresses::new(&cfg, Box::new(fixed.clone()));
        own.refresh(T0);
        // the first look-up and an unchanged set say nothing
        assert!(captured_log().is_empty());
        fixed.set_local(Ok(ip("192.0.2.201")));
        own.refresh(T0 + 30);
        assert_eq!(
            captured_log(),
            vec![
                "INFO own addresses changed: added 192.0.2.201, removed 192.0.2.200; now router \
                 192.0.2.1 from 192.0.2.201, nvr1 192.0.2.5 from 192.0.2.201"
            ]
        );
        assert_eq!(set(&own), ["192.0.2.1", "192.0.2.5", "192.0.2.201"]);
    }

    #[test]
    fn a_failed_look_up_keeps_what_was_last_found() {
        let fixed = Fixed::new(LOCAL);
        fixed.set_name("nvr.example.net", Ok(vec![ip("198.51.100.5")]));
        let cfg = config(
            Some("https://192.0.2.1"),
            &[("nvr1", "https://nvr.example.net")],
        );
        let mut own = OwnAddresses::new(&cfg, Box::new(fixed.clone()));
        // the first poll; the name was resolved at startup
        own.refresh(T0);
        let before = set(&own);
        capture_log();
        fixed.set_name(
            "nvr.example.net",
            Err("cannot resolve: timed out".to_string()),
        );
        fixed.set_local(Err("no route".to_string()));
        own.refresh(T0 + RESOLVE_EVERY);
        assert_eq!(set(&own), before);
        assert_eq!(
            captured_log(),
            vec![
                "WARNING own addresses: the look-up for router failed, its last known addresses \
                 stay: no route",
                "WARNING own addresses: the look-up for nvr1 failed, its last known addresses \
                 stay: cannot resolve: timed out; no route",
            ]
        );
        assert_eq!(
            own.failures(),
            vec![
                "router: no route",
                "nvr1: cannot resolve: timed out; no route"
            ]
        );
        // the same reason again is not logged again
        own.refresh(T0 + 2 * RESOLVE_EVERY);
        assert!(captured_log().is_empty());
        // a name that now resolves elsewhere: the new address, and the old
        // one's local address is no longer kept
        fixed.set_name("nvr.example.net", Ok(vec![ip("198.51.100.6")]));
        fixed.set_local(Ok(LOCAL));
        own.refresh(T0 + 3 * RESOLVE_EVERY);
        assert_eq!(
            captured_log(),
            vec![
                "INFO own addresses: the look-up for router works again",
                "INFO own addresses: the look-up for nvr1 works again",
                "INFO own addresses changed: added 198.51.100.6, removed 198.51.100.5; now router \
                 192.0.2.1 from 192.0.2.200, nvr1 198.51.100.6 from 192.0.2.200",
            ]
        );
        assert!(own.failures().is_empty());
    }

    /// The local address is asked for in every poll, a host name at most
    /// every `RESOLVE_EVERY` (and at once at startup), an IPv4 address in a
    /// URL never.
    #[test]
    fn names_are_resolved_now_and_then_and_addresses_never() {
        let fixed = Fixed::new(LOCAL);
        fixed.set_name("nvr.example.net", Ok(vec![ip("198.51.100.5")]));
        let cfg = config(
            Some("https://192.0.2.1"),
            &[("nvr1", "https://nvr.example.net")],
        );
        let mut own = OwnAddresses::new(&cfg, Box::new(fixed.clone()));
        assert_eq!(fixed.resolved(), 1, "the name, at once");
        // polls every 30 s: the local address follows at once, the name
        // keeps its answer
        fixed.set_name("nvr.example.net", Ok(vec![ip("198.51.100.6")]));
        for poll in 0..10 {
            own.refresh(T0 + poll * 30);
        }
        assert_eq!(fixed.resolved(), 1);
        fixed.set_local(Ok(ip("192.0.2.201")));
        own.refresh(T0 + 300 - 1);
        assert_eq!(fixed.resolved(), 1);
        assert_eq!(
            set(&own),
            ["192.0.2.1", "192.0.2.201", "198.51.100.5"],
            "a new local address at once"
        );
        // the interval has passed since the first poll
        own.refresh(T0 + RESOLVE_EVERY);
        assert_eq!(fixed.resolved(), 2);
        assert_eq!(set(&own), ["192.0.2.1", "192.0.2.201", "198.51.100.6"]);
    }

    #[test]
    fn a_device_never_found_is_named() {
        let fixed = Fixed::new(LOCAL);
        let cfg = config(None, &[("nvr1", "https://nvr.example.net")]);
        let own = OwnAddresses::new(&cfg, Box::new(fixed));
        // the local address is found per device address: none here
        assert!(own.set().is_empty());
        assert_eq!(own.describe(), "nvr1 not found");
        assert_eq!(
            own.failures(),
            vec!["nvr1: cannot resolve nvr.example.net: no such name"]
        );
    }

    #[test]
    fn urls_give_host_and_port() {
        for (url, host, port) in [
            ("http://192.0.2.1", "192.0.2.1", 80),
            ("https://192.0.2.1", "192.0.2.1", 443),
            ("http://192.0.2.1:8080", "192.0.2.1", 8080),
            ("https://nvr.example.net:8443", "nvr.example.net", 8443),
            ("http://[2001:db8::1]:8080", "2001:db8::1", 8080),
            ("https://[2001:db8::1]", "2001:db8::1", 443),
        ] {
            let d = Device::of("x", url);
            assert_eq!((d.host.as_str(), d.port), (host, port), "{}", url);
        }
    }

    /// The operating system's adapter, on loopback only: no packet leaves
    /// the host and no name server is asked.
    #[test]
    fn the_system_finds_loopback() {
        let mut system = System;
        assert_eq!(
            system.resolve("127.0.0.1", 80).unwrap(),
            vec![Ipv4Addr::LOCALHOST]
        );
        assert_eq!(
            system.local_toward(Ipv4Addr::LOCALHOST, 80).unwrap(),
            Ipv4Addr::LOCALHOST
        );
        let cfg = config(
            Some("http://127.0.0.1:8728"),
            &[("nvr1", "http://127.0.0.1")],
        );
        let own = OwnAddresses::new(&cfg, Box::new(System));
        assert_eq!(set(&own), ["127.0.0.1"]);
        assert!(own.to_ask().is_empty());
        assert_eq!(
            own.describe(),
            "router 127.0.0.1 from 127.0.0.1, nvr1 127.0.0.1 from 127.0.0.1"
        );
    }
}
