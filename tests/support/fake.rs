//! The fakes shared by `tests/e2e.rs` and `tests/sim.rs`: NVRs (with real
//! digest verification), the RouterOS REST API and the Telegram Bot API, all
//! served in-process, and the `Harness` that drives an engine against them.
//!
//! The host clock is driven by the tests (`Engine::cycle_at`). Each fake
//! NVR's clock is the host clock plus its own `skew`; by default a device
//! shows local time two hours ahead of UTC, as an NVR set to UTC+2 does.

#![allow(dead_code)]

use hik_f2b::config::Config;
use hik_f2b::engine::Engine;
use hik_f2b::nvr::parse_kv;
use hik_f2b::state::State;
use hik_f2b::util;
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
pub const DAY: &str = "2026-01-10T";
pub const ATTACKER: &str = "198.51.100.7";
pub const OWNER: &str = "203.0.113.20";
const NONCE: &str = "n0nce";
pub const TOKEN: &str = "123456:TEST_token-x";
/// Device local time minus host (UTC) time.
pub const SKEW: i64 = 7200;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    pub ts: String, // device time, YYYY-MM-DDTHH:MM:SS
    pub minor: String,
    pub ip: String,
    pub user: Vec<u8>, // inserted into the XML as is (may be XML-escaped, may be broken)
}

#[derive(Default)]
pub struct Fake {
    // --- NVR
    pub now: String,
    pub skew: i64,
    pub entries: Vec<Entry>,
    pub nvr_auth_ok: bool,
    pub nonce: String,
    /// Change the nonce every N ISAPI requests, without stale=true.
    pub rotate_every: Option<u32>,
    pub rotations: u32,
    /// Send a Basic challenge header before the Digest one.
    pub basic_first: bool,
    /// Newest entries first instead of oldest first.
    pub newest_first: bool,
    /// Ignore searchResultPostion and always claim MORE (broken firmware).
    pub stuck_paging: bool,
    /// A search window containing this device time gets an unparseable page.
    pub poison: Option<String>,
    /// Hand-written replies for the next searches, served before anything else.
    pub raw_pages: VecDeque<Vec<u8>>,
    pub isapi_requests: u32,
    pub isapi_ok: u32,
    pub challenges: u32,
    pub search_requests: u32,
    pub refused_logins: u32,
    /// Drop ISAPI connections without an answer.
    pub nvr_down: bool,
    /// Answer every log search with a page that cannot be parsed.
    pub garbage: bool,
    // --- router
    pub bans: Vec<String>,
    pub ban_bodies: Vec<String>,
    pub router_down: bool,
    /// Drop REST connections without an answer.
    pub router_unreachable: bool,
    /// Answer reads, refuse every PUT: a router user whose group lacks the
    /// `write` policy.
    pub refuse_writes: bool,
    pub router_requests: u32,
    /// Error detail for a duplicate entry; `None` = today's RouterOS text.
    pub duplicate_text: Option<String>,
    /// Firewall rules as (table, src-address-list, disabled).
    pub rules: Vec<(&'static str, String, bool)>,
    /// `path?query` of every rule lookup.
    pub rule_queries: Vec<String>,
    /// `query` of every address-list lookup by address.
    pub lookups: Vec<String>,
    pub identity_requests: u32,
    /// (address, outcome) of every PUT that reached the router: `accepted`,
    /// `duplicate`, `refused`, `refused-listed` (refused, but the address is
    /// listed) or `down`.
    pub put_log: Vec<(String, &'static str)>,
    // --- Telegram
    pub tg_sent: Vec<String>,
    pub tg_attempts: u32,
    pub tg_fail: bool,
}

fn between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let Some(i) = text.find(start) else {
        return "";
    };
    let rest = &text[i + start.len()..];
    &rest[..rest.find(end).unwrap_or(rest.len())]
}

fn digest_ok(method: &str, path: &str, auth: &str, nonce: &str) -> bool {
    let Some(rest) = auth.strip_prefix("Digest ") else {
        return false;
    };
    let kv = parse_kv(rest);
    let get = |k: &str| {
        kv.iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    };
    let ha1 = util::md5_hex("f2b:fake:secret");
    let ha2 = util::md5_hex(&format!("{}:{}", method, path));
    let expected = util::md5_hex(&format!(
        "{}:{}:{}:{}:auth:{}",
        ha1,
        nonce,
        get("nc"),
        get("cnonce"),
        ha2
    ));
    get("username") == "f2b"
        && get("nonce") == nonce
        && get("uri") == path
        && get("response") == expected
}

/// (status, extra header lines, content type, body)
type Reply = (u16, String, &'static str, Vec<u8>);

fn reply(code: u16, ctype: &'static str, body: impl Into<Vec<u8>>) -> Reply {
    (code, String::new(), ctype, body.into())
}

fn search_page(f: &mut Fake, body: &str) -> Vec<u8> {
    let start = between(body, "<startTime>", "Z</startTime>").to_string();
    let end = between(body, "<endTime>", "Z</endTime>").to_string();
    if f.garbage {
        return b"<?xml version=\"1.0\"?>\n<<< this is not a result page".to_vec();
    }
    if let Some(p) = &f.poison {
        if start.as_str() <= p.as_str() && p.as_str() <= end.as_str() {
            return b"<?xml version=\"1.0\"?>\n<<< this is not a result page".to_vec();
        }
    }
    let mut pos: usize = between(body, "<searchResultPostion>", "<").parse().unwrap();
    let asked: usize = between(body, "<maxResults>", "<").parse().unwrap();
    let size = asked.min(64); // real devices cap a page below what was asked for
    let mut matching: Vec<&Entry> = f
        .entries
        .iter()
        .filter(|e| start.as_str() <= e.ts.as_str() && e.ts.as_str() <= end.as_str())
        .collect();
    if f.newest_first {
        matching.reverse();
    }
    if f.stuck_paging {
        pos = 0;
    }
    let page: Vec<&&Entry> = matching.iter().skip(pos).take(size).collect();
    let status = if f.stuck_paging || pos + size < matching.len() {
        "MORE"
    } else if page.is_empty() {
        "NO MATCHES"
    } else {
        "OK"
    };
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<CMSearchResult version=\"1.0\" \
         xmlns=\"http://www.hikvision.com/ver20/XMLSchema\">\n<searchID>{{x}}</searchID>\n\
         <responseStatus>true</responseStatus>\n<responseStatusStrg>{}</responseStatusStrg>\n\
         <numOfMatches>{}</numOfMatches>\n<matchList>\n",
        status,
        page.len()
    )
    .into_bytes();
    for e in page {
        out.extend_from_slice(
            format!(
                "<searchMatchItem>\n<logDescriptor>\n\
                 <metaId>log.hikvision.com/Exception/{}</metaId>\n\
                 <StartDateTime>{}Z</StartDateTime>\n<paraType></paraType>\n<userName>",
                e.minor, e.ts
            )
            .as_bytes(),
        );
        out.extend_from_slice(&e.user);
        out.extend_from_slice(
            format!(
                "</userName>\n<ipAddress>{}</ipAddress>\n</logDescriptor>\n</searchMatchItem>\n",
                e.ip
            )
            .as_bytes(),
        );
    }
    out.extend_from_slice(b"</matchList>\n</CMSearchResult>\n");
    out
}

/// The reply code that makes `serve` drop the connection without an answer.
const DROP: u16 = 0;

/// The value of `key` in a query string.
fn param(query: &str, key: &str) -> Option<String> {
    form(query)
        .into_iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
}

fn route(
    fake: &Mutex<Fake>,
    method: &str,
    path: &str,
    query: &str,
    auth: &str,
    body: &str,
) -> Reply {
    let mut f = fake.lock().unwrap();
    let xml = "application/xml";
    let json = "application/json";
    if path.starts_with("/ISAPI/") && f.nvr_down {
        return reply(DROP, xml, "");
    }
    if path.starts_with("/rest/") {
        if f.router_unreachable {
            return reply(DROP, json, "");
        }
        if auth != format!("Basic {}", util::b64(b"f2b:rpass")) {
            return reply(401, json, "{\"error\":401,\"message\":\"Unauthorized\"}");
        }
    }
    if method == "GET" && (path == "/rest/ip/firewall/raw" || path == "/rest/ip/firewall/filter") {
        f.rule_queries.push(format!("{}?{}", path, query));
        let table = path.trim_start_matches("/rest/ip/firewall/");
        let list = param(query, "src-address-list");
        let wanted = param(query, "disabled");
        let proplist = param(query, ".proplist").unwrap_or_default();
        // As on RouterOS 7.18.1: enabled `raw` rules have no `disabled`
        // member at all (so a `disabled=false` filter misses them); `filter`
        // rules always have one.
        let shown = |t: &str, d: bool| -> Option<&'static str> {
            match (d, t) {
                (true, _) => Some("true"),
                (false, "filter") => Some("false"),
                (false, _) => None,
            }
        };
        let ids: Vec<String> = f
            .rules
            .iter()
            .enumerate()
            .filter(|(_, (t, l, d))| {
                *t == table
                    && list.as_ref().is_none_or(|want| want == l)
                    && wanted
                        .as_ref()
                        .is_none_or(|want| shown(t, *d) == Some(want.as_str()))
            })
            .map(|(n, (t, _, d))| {
                let mut member = format!("{{\".id\":\"*{:X}\"", n + 1);
                if let Some(v) = shown(t, *d) {
                    if proplist.split(',').any(|p| p == "disabled") {
                        member.push_str(&format!(",\"disabled\":\"{}\"", v));
                    }
                }
                member.push('}');
                member
            })
            .collect();
        return reply(200, json, format!("[{}]", ids.join(",")));
    }
    if method == "GET" && path == "/rest/system/identity" {
        f.identity_requests += 1;
        return reply(200, json, "{\"name\":\"fake\"}");
    }
    if path.starts_with("/ISAPI/") {
        f.isapi_requests += 1;
        if let Some(n) = f.rotate_every {
            if f.isapi_requests.is_multiple_of(n) {
                f.rotations += 1;
                f.nonce = format!("{}-{}", NONCE, f.rotations);
            }
        }
        if !f.nvr_auth_ok || !digest_ok(method, path, auth, &f.nonce) {
            if !auth.is_empty() {
                f.refused_logins += 1;
            }
            f.challenges += 1;
            let mut challenge = String::new();
            if f.basic_first {
                challenge.push_str("WWW-Authenticate: Basic realm=\"fake\"\r\n");
            }
            challenge.push_str(&format!(
                "WWW-Authenticate: Digest realm=\"fake\", domain=\"/\", qop=\"auth\", nonce=\"{}\", \
                 opaque=\"0paque\", algorithm=\"MD5\", stale=\"FALSE\"\r\n",
                f.nonce
            ));
            return (401, challenge, xml, b"<x/>".to_vec());
        }
        f.isapi_ok += 1;
        if path == "/ISAPI/System/time" {
            let out = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<Time version=\"1.0\" \
                 xmlns=\"http://www.hikvision.com/ver20/XMLSchema\">\n<timeMode>NTP</timeMode>\n\
                 <localTime>{}+02:00</localTime>\n</Time>\n",
                f.now
            );
            return reply(200, xml, out);
        }
        if path == "/ISAPI/ContentMgmt/logSearch" && method == "POST" {
            f.search_requests += 1;
            let out = match f.raw_pages.pop_front() {
                Some(raw) => raw,
                None => search_page(&mut f, body),
            };
            return reply(200, xml, out);
        }
    }
    if path.starts_with("/rest/ip/firewall/address-list") {
        f.router_requests += 1;
        if method == "GET" && param(query, "address").is_some() {
            f.lookups.push(query.to_string());
            let list = param(query, "list").unwrap_or_default();
            let address = param(query, "address").unwrap_or_default();
            let found = list == "cctv_ban" && f.bans.contains(&address);
            let out = if found { "[{\".id\":\"*1\"}]" } else { "[]" };
            return reply(200, json, out);
        }
        if method == "GET" {
            let list: Vec<String> = f
                .bans
                .iter()
                .map(|a| format!("{{\"address\":\"{}\"}}", a))
                .collect();
            return reply(200, json, format!("[{}]", list.join(",")));
        }
        if method == "PUT" {
            let address = between(body, "\"address\":\"", "\"").to_string();
            let listed = f.bans.contains(&address);
            if f.router_down {
                f.put_log.push((address, "down"));
                return reply(500, json, "{\"error\":500,\"message\":\"down\"}");
            }
            if f.refuse_writes {
                let outcome = if listed { "refused-listed" } else { "refused" };
                f.put_log.push((address, outcome));
                // RouterOS error format; the detail is the console's text
                // for a missing policy
                return reply(
                    400,
                    json,
                    "{\"detail\":\"not enough permissions (9)\",\"error\":400,\
                     \"message\":\"Bad Request\"}",
                );
            }
            if listed {
                f.put_log.push((address, "duplicate"));
                let detail = f
                    .duplicate_text
                    .clone()
                    .unwrap_or_else(|| "failure: already have such entry".to_string());
                let out = format!(
                    "{{\"detail\":\"{}\",\"error\":400,\"message\":\"Bad Request\"}}",
                    detail
                );
                return reply(400, json, out);
            }
            f.put_log.push((address.clone(), "accepted"));
            f.bans.push(address);
            f.ban_bodies.push(body.to_string());
            return reply(201, json, "{}");
        }
    }
    if path == format!("/bot{}/sendMessage", TOKEN) && method == "POST" {
        f.tg_attempts += 1;
        if f.tg_fail {
            let out = format!(
                "{{\"ok\":false,\"description\":\"boom at /bot{}/x\"}}",
                TOKEN
            );
            return reply(500, json, out);
        }
        f.tg_sent.push(body.to_string());
        return reply(200, json, "{\"ok\":true}");
    }
    reply(404, "text/plain", "not found")
}

fn serve(stream: TcpStream, fake: Arc<Mutex<Fake>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut stream = stream;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let target = parts.next().unwrap_or("").to_string();
        let (path, query) = target.split_once('?').unwrap_or((&target, ""));
        let (path, query) = (path.to_string(), query.to_string());
        let (mut length, mut auth) = (0usize, String::new());
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap_or(0) == 0 {
                return;
            }
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            if let Some((k, v)) = header.split_once(':') {
                match k.to_ascii_lowercase().as_str() {
                    "content-length" => length = v.trim().parse().unwrap_or(0),
                    "authorization" => auth = v.trim().to_string(),
                    _ => {}
                }
            }
        }
        let mut body = vec![0u8; length];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        let body = String::from_utf8_lossy(&body).to_string();
        let (code, headers, ctype, out) = route(&fake, &method, &path, &query, &auth, &body);
        if code == DROP {
            return;
        }
        let head = format!(
            "HTTP/1.1 {} X\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}\r\n",
            code,
            ctype,
            out.len(),
            headers
        );
        if stream.write_all(head.as_bytes()).is_err() || stream.write_all(&out).is_err() {
            return;
        }
    }
}

/// Starts a fake on its own port.
fn spawn_fake() -> (Arc<Mutex<Fake>>, u16) {
    let fake = Arc::new(Mutex::new(Fake {
        skew: SKEW,
        nvr_auth_ok: true,
        nonce: NONCE.to_string(),
        // the drop rule from the README
        rules: vec![("raw", "cctv_ban".to_string(), false)],
        ..Default::default()
    }));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let shared = Arc::clone(&fake);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || serve(stream, shared));
        }
    });
    (fake, port)
}

pub fn attacker() -> Ipv4Addr {
    ATTACKER.parse().unwrap()
}

pub fn ip(text: &str) -> Ipv4Addr {
    text.parse().unwrap()
}

/// Device time as the fake NVR prints it.
pub fn device(ts: i64) -> String {
    util::fmt_ts(ts).trim_end_matches('Z').to_string()
}

/// Host time at which the default device clock shows `DAY` + `clock`.
pub fn host_of(clock: &str) -> i64 {
    util::parse_ts(&format!("{}{}", DAY, clock)).unwrap() - SKEW
}

/// Decodes `application/x-www-form-urlencoded` into pairs.
pub fn form(body: &str) -> Vec<(String, String)> {
    let decode = |s: &str| {
        let b = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'+' => out.push(b' '),
                b'%' if i + 2 < b.len() => {
                    let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap();
                    out.push(u8::from_str_radix(hex, 16).unwrap());
                    i += 2;
                }
                c => out.push(c),
            }
            i += 1;
        }
        String::from_utf8(out).unwrap()
    };
    body.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(k), decode(v))
        })
        .collect()
}

pub fn text_of(body: &str) -> String {
    form(body)
        .into_iter()
        .find(|(k, _)| k == "text")
        .map(|(_, v)| v)
        .unwrap()
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);

pub struct Opts {
    pub telegram: bool,
    pub mikrotik: bool,
    pub second_nvr: bool,
    pub general: &'static str,
    /// Extra lines for the [mikrotik] and [telegram] sections.
    pub mikrotik_extra: &'static str,
    pub telegram_extra: &'static str,
}

impl Default for Opts {
    fn default() -> Opts {
        Opts {
            telegram: false,
            mikrotik: true,
            second_nvr: false,
            general: "",
            mikrotik_extra: "",
            telegram_extra: "",
        }
    }
}

pub struct Harness {
    pub fake: Arc<Mutex<Fake>>,
    pub fake2: Option<Arc<Mutex<Fake>>>,
    pub engine: Engine,
    pub dir: PathBuf,
    pub ini: String,
    pub port: u16,
    pub host: i64,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Harness {
    /// A harness whose engine has not polled yet.
    pub fn build(opts: Opts) -> Harness {
        let (fake, port) = spawn_fake();
        let dir = std::env::temp_dir().join(format!(
            "hik-f2b-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut ini = format!(
            "[general]\nmaxretry = 5\nfindtime = 3600\nbantime = 86400\nstate_file = {}\n{}\n\
             [nvr:nvr1]\nurl = http://127.0.0.1:{port}\nuser = f2b\npassword = secret\n",
            dir.join("state").display(),
            opts.general,
            port = port
        );
        if opts.mikrotik {
            ini.push_str(&format!(
                "[mikrotik]\nurl = http://127.0.0.1:{}\nuser = f2b\npassword = rpass\n{}\n",
                port, opts.mikrotik_extra
            ));
        }
        let fake2 = if opts.second_nvr {
            let (fake2, port2) = spawn_fake();
            ini.push_str(&format!(
                "[nvr:nvr2]\nurl = http://127.0.0.1:{}\nuser = f2b\npassword = secret\n",
                port2
            ));
            Some(fake2)
        } else {
            None
        };
        if opts.telegram {
            ini.push_str(&format!(
                "[telegram]\napi_url = http://127.0.0.1:{}\nbot_token = {}\n\
                 chat_id = -1001234567890\n{}\nmessage_thread_id = 42\n",
                port, TOKEN, opts.telegram_extra
            ));
        }
        let engine = Engine::new(Config::parse(&ini).unwrap(), State::default()).unwrap();
        let mut h = Harness {
            fake,
            fake2,
            engine,
            dir,
            ini,
            port,
            host: 0,
        };
        h.set_host(host_of("10:00:00"));
        h
    }

    pub fn raw(telegram: bool) -> Harness {
        Harness::build(Opts {
            telegram,
            ..Default::default()
        })
    }

    /// A harness after its first poll, which records the starting point
    /// (and, as seen, what the overlap before it holds).
    pub fn with(opts: Opts) -> Harness {
        let mut h = Harness::build(opts);
        h.tick();
        h
    }

    pub fn new(telegram: bool) -> Harness {
        Harness::with(Opts {
            telegram,
            ..Default::default()
        })
    }

    pub fn fakes(&self) -> Vec<Arc<Mutex<Fake>>> {
        let mut all = vec![Arc::clone(&self.fake)];
        all.extend(self.fake2.iter().cloned());
        all
    }

    /// Sets the host clock; every device clock follows with its own skew.
    pub fn set_host(&mut self, host: i64) {
        self.host = host;
        for fake in self.fakes() {
            let mut f = fake.lock().unwrap();
            f.now = device(host + f.skew);
        }
    }

    pub fn tick(&mut self) {
        let host = self.host;
        self.set_host(host);
        self.engine.cycle_at(host as u64);
    }

    /// Runs a cycle at the host time when the default device clock shows
    /// `DAY` + `clock`.
    pub fn cycle(&mut self, clock: &str) {
        self.set_host(host_of(clock));
        self.engine.cycle_at(self.host as u64);
    }

    /// Runs a cycle `seconds` after the previous one.
    pub fn advance(&mut self, seconds: i64) {
        self.set_host(self.host + seconds);
        self.engine.cycle_at(self.host as u64);
    }

    pub fn entry_to(fake: &Mutex<Fake>, ts: &str, ip: &str, user: &[u8], minor: &str) {
        let mut f = fake.lock().unwrap();
        f.entries.push(Entry {
            ts: ts.to_string(),
            minor: minor.to_string(),
            ip: ip.to_string(),
            user: user.to_vec(),
        });
        f.entries.sort();
    }

    pub fn add_full(&self, clock: &str, ip: &str, user: &str, minor: &str) {
        Harness::entry_to(
            &self.fake,
            &format!("{}{}", DAY, clock),
            ip,
            user.as_bytes(),
            minor,
        );
    }

    pub fn add(&self, clock: &str, ip: &str) {
        self.add_full(clock, ip, "admin", "illlegealAccess");
    }

    /// A failed login at a full device time stamp on the given fake.
    pub fn add_at(fake: &Mutex<Fake>, ts: &str, ip: &str) {
        Harness::entry_to(fake, ts, ip, b"admin", "illlegealAccess");
    }

    pub fn burst(&self, minute: &str, ip: &str, count: usize) {
        for second in 10..10 + count {
            self.add(&format!("{}:{}", minute, second), ip);
        }
    }

    pub fn banned(&self) -> Vec<String> {
        self.fake.lock().unwrap().bans.clone()
    }

    pub fn fails(&self, address: &str) -> usize {
        self.engine
            .state
            .fails
            .get(&ip(address))
            .map(|t| t.len())
            .unwrap_or(0)
    }

    pub fn since(&self, nvr: &str) -> String {
        device(self.engine.state.nvr[nvr].since)
    }

    /// Saves the state, loads it again and starts a new engine with it, as
    /// a restart of the daemon does.
    pub fn restart(&mut self) {
        let path = self.dir.join("state");
        self.engine.state.save(&path).unwrap();
        let restored = State::load(&path);
        assert_eq!(restored, self.engine.state, "state file round trip");
        self.engine = Engine::new(Config::parse(&self.ini).unwrap(), restored).unwrap();
    }
}

/// Runs `n` cycles, `step` seconds apart.
pub fn run(h: &mut Harness, n: usize, step: i64) {
    for _ in 0..n {
        h.advance(step);
    }
}

pub fn logged(lines: &[String], needle: &str) -> usize {
    lines.iter().filter(|l| l.contains(needle)).count()
}
