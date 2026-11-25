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
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
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

/// A firewall rule on the fake router.
#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    pub table: &'static str,
    /// Its `src-address-list`.
    pub list: String,
    pub disabled: bool,
    /// RouterOS marks a rule invalid when, for example, the interface list
    /// it names is removed; the rule then matches nothing.
    pub invalid: bool,
    pub dynamic: bool,
}

impl Rule {
    pub fn new(table: &'static str, list: &str, disabled: bool) -> Rule {
        Rule {
            table,
            list: list.to_string(),
            disabled,
            invalid: false,
            dynamic: false,
        }
    }

    pub fn invalid(table: &'static str, list: &str) -> Rule {
        Rule {
            invalid: true,
            ..Rule::new(table, list, false)
        }
    }

    pub fn dynamic(table: &'static str, list: &str) -> Rule {
        Rule {
            dynamic: true,
            ..Rule::new(table, list, false)
        }
    }
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
    /// Answer every REST request with this HTTP status (401: a wrong
    /// password, 403, 5xx), in RouterOS's error format.
    pub rest_status: Option<u16>,
    /// Answer every PUT with this HTTP status, reads work.
    pub put_status: Option<u16>,
    /// Answer every REST request with HTTP 200 and an HTML page, as a proxy
    /// in front of the router might.
    pub rest_html: bool,
    /// Every REST request that reached the router.
    pub rest_requests: u32,
    /// Set this flag when a PUT arrives (a stop signal in the middle of a
    /// cycle).
    pub stop_on_put: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Firewall rules.
    pub rules: Vec<Rule>,
    /// `path?query` of every rule lookup.
    pub rule_queries: Vec<String>,
    /// `query` of every address-list lookup by address.
    pub lookups: Vec<String>,
    pub identity_requests: u32,
    /// (address, outcome) of every PUT that reached the router: `accepted`,
    /// `duplicate`, `refused`, `refused-listed` (refused, but the address is
    /// listed), `down` or `status` (answered with `rest_status` or
    /// `put_status`).
    pub put_log: Vec<(String, &'static str)>,
    // --- Telegram
    pub tg_sent: Vec<String>,
    pub tg_attempts: u32,
    pub tg_fail: bool,
    /// Accept this many messages in all, then answer HTTP 429 with
    /// `retry_after` 30, as Telegram does when a chat gets too many.
    pub tg_accept: Option<usize>,
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
        f.rest_requests += 1;
        if f.rest_html {
            return reply(
                200,
                "text/html",
                "<html><head><title>Proxy</title></head><body>Please log in</body></html>",
            );
        }
        let status = f.rest_status.or(f.put_status.filter(|_| method == "PUT"));
        if let Some(code) = status {
            if path.starts_with("/rest/ip/firewall/address-list") && method == "PUT" {
                let address = between(body, "\"address\":\"", "\"").to_string();
                f.put_log.push((address, "status"));
            }
            let message = match code {
                401 => "Unauthorized",
                403 => "Forbidden",
                404 => "Not Found",
                503 => "Service Unavailable",
                _ => "Internal Server Error",
            };
            return reply(
                code,
                json,
                format!("{{\"error\":{},\"message\":\"{}\"}}", code, message),
            );
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
        let asked = |p: &str| proplist.split(',').any(|q| q == p);
        // As on RouterOS 7.18.1 (`.proplist=.id,disabled,invalid,dynamic`):
        // `disabled` is `"true"` on a disabled rule, `"false"` on some
        // enabled rules and missing on others (so a `disabled=false` filter
        // misses them), in `raw` as in `filter`; `invalid` is `"false"` on an
        // ordinary rule; a dynamic rule has only `"dynamic":"true"`.
        let shown = |n: usize, r: &Rule| -> Option<&'static str> {
            match (r.dynamic, r.disabled) {
                (true, _) => None,
                (false, true) => Some("true"),
                (false, false) if n % 2 == 1 => Some("false"),
                (false, false) => None,
            }
        };
        let ids: Vec<String> = f
            .rules
            .iter()
            .enumerate()
            .filter(|(n, r)| {
                r.table == table
                    && list.as_ref().is_none_or(|want| *want == r.list)
                    && wanted
                        .as_ref()
                        .is_none_or(|want| shown(*n, r) == Some(want.as_str()))
            })
            .map(|(n, r)| {
                let mut member = format!("{{\".id\":\"*{:X}\"", n + 1);
                if let Some(v) = shown(n, r) {
                    if asked("disabled") {
                        member.push_str(&format!(",\"disabled\":\"{}\"", v));
                    }
                }
                if !r.dynamic && asked("invalid") {
                    member.push_str(&format!(",\"invalid\":\"{}\"", r.invalid));
                }
                if r.dynamic && asked("dynamic") {
                    member.push_str(",\"dynamic\":\"true\"");
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
            if let Some(flag) = &f.stop_on_put {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }
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
            f.bans.push(address.clone());
            f.ban_bodies.push(body.to_string());
            // RouterOS answers with the entry it made
            let out = format!(
                "{{\".id\":\"*{:X}\",\"address\":\"{}\",\"list\":\"cctv_ban\"}}",
                f.bans.len(),
                address
            );
            return reply(201, json, out);
        }
    }
    if path == format!("/bot{}/sendMessage", TOKEN) && method == "POST" {
        f.tg_attempts += 1;
        if f.tg_accept.is_some_and(|n| f.tg_sent.len() >= n) {
            return reply(
                429,
                json,
                "{\"ok\":false,\"error_code\":429,\"description\":\"Too Many Requests: retry \
                 after 30\",\"parameters\":{\"retry_after\":30}}",
            );
        }
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
    let _ = stream.set_nodelay(true);
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
        // One write: a second small one would wait for the client's
        // delayed ACK (Nagle), some 40 ms per request.
        let mut reply = head.into_bytes();
        reply.extend_from_slice(&out);
        if stream.write_all(&reply).is_err() {
            return;
        }
    }
}

// --- The servers' threads and sockets
//
// Each fake runs a listener thread and one thread per connection. A dropped
// `Harness` stops them all (`FakeServer::stop`) and these counters, which
// cover every fake in the process, show that it did: `tests/fake_leak.rs`
// and the summary line of each class in `tests/sim.rs` check them.

/// Live listener and connection threads of the fakes.
static LIVE_THREADS: AtomicUsize = AtomicUsize::new(0);
/// The most `LIVE_THREADS` has been.
static PEAK_THREADS: AtomicUsize = AtomicUsize::new(0);
/// Listening sockets of the fakes that are open.
static OPEN_LISTENERS: AtomicUsize = AtomicUsize::new(0);
/// Failed accepts on the fakes' listeners.
static ACCEPT_ERRORS: AtomicUsize = AtomicUsize::new(0);
/// The most entries seen in the connection tracking table (`conntrack`),
/// and its size.
static CONNTRACK_PEAK: Mutex<Option<(u64, u64)>> = Mutex::new(None);
/// How long a dropped harness waits for its fakes' threads to end.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Live listener and connection threads of the fakes in this process.
pub fn live_threads() -> usize {
    LIVE_THREADS.load(Ordering::SeqCst)
}

/// The most live fake threads there have been in this process.
pub fn peak_threads() -> usize {
    PEAK_THREADS.load(Ordering::SeqCst)
}

/// Open listening sockets of the fakes in this process.
pub fn open_listeners() -> usize {
    OPEN_LISTENERS.load(Ordering::SeqCst)
}

/// Failed accepts on the fakes' listeners in this process (each one also
/// goes into the message of a stop that does not end).
pub fn accept_errors() -> usize {
    ACCEPT_ERRORS.load(Ordering::SeqCst)
}

/// On Linux, the entries in the kernel's connection tracking table and
/// its size, when the table is in use (`None` otherwise). Every loopback
/// connection of the tests takes an entry, which stays for two minutes
/// after the connection closed. When the table is full, the kernel drops
/// the packets of new connections: a connection to a fake then times out,
/// although the fake is listening.
pub fn conntrack() -> Option<(u64, u64)> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let read = |name: &str| -> Option<u64> {
        std::fs::read_to_string(format!("/proc/sys/net/netfilter/{}", name))
            .ok()?
            .trim()
            .parse()
            .ok()
    };
    Some((read("nf_conntrack_count")?, read("nf_conntrack_max")?))
}

/// Takes a sample of the connection tracking table for `conntrack_peak`
/// (each dropped harness does).
pub fn sample_conntrack() {
    if let Some((count, max)) = conntrack() {
        let mut peak = CONNTRACK_PEAK.lock().unwrap_or_else(|e| e.into_inner());
        let most = peak.map_or(0, |(c, _)| c).max(count);
        *peak = Some((most, max));
    }
}

/// The most entries the samples found in the connection tracking table,
/// and its size (`None` where there is no table).
pub fn conntrack_peak() -> Option<(u64, u64)> {
    *CONNTRACK_PEAK.lock().unwrap_or_else(|e| e.into_inner())
}

/// The state of the connection tracking table, for a failure that a full
/// table can cause (empty where there is no table).
pub fn conntrack_note() -> String {
    match conntrack() {
        Some((count, max)) => format!(
            "; the kernel's connection tracking table holds {} of {} entries{}",
            count,
            max,
            if count >= max {
                ": it is full, so the kernel drops new connections (see sim.yml)"
            } else {
                ""
            }
        ),
        None => String::new(),
    }
}

/// One live fake thread, from before it is spawned until it ends (also by
/// a panic, or when the spawn fails and the closure is dropped).
struct Counted;

impl Counted {
    fn new() -> Counted {
        let live = LIVE_THREADS.fetch_add(1, Ordering::SeqCst) + 1;
        PEAK_THREADS.fetch_max(live, Ordering::SeqCst);
        Counted
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        LIVE_THREADS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A listening socket, counted while it is open.
struct Listening(TcpListener);

impl Listening {
    fn bind() -> Listening {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        OPEN_LISTENERS.fetch_add(1, Ordering::SeqCst);
        Listening(listener)
    }
}

impl Drop for Listening {
    fn drop(&mut self) {
        OPEN_LISTENERS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// What a fake's threads share with its `FakeServer`.
#[derive(Default)]
struct Threads {
    /// Set before the listener is woken to stop.
    stop: bool,
    /// The listener thread has not ended yet.
    listening: bool,
    /// A clone of each open connection, so that `stop` can shut it down.
    open: HashMap<u64, TcpStream>,
    next: u64,
    /// Connection threads that have not ended yet.
    live: usize,
    /// Connection threads not joined yet (finished ones are joined as new
    /// connections arrive).
    handles: Vec<JoinHandle<()>>,
    /// Failed accepts (or clones of an accepted connection) and the last
    /// error.
    accept_errors: usize,
    last_accept_error: Option<String>,
    /// The error of the connection that `stop` makes to wake the listener,
    /// if it failed.
    wake_error: Option<String>,
}

type Shared = Arc<(Mutex<Threads>, Condvar)>;

fn lock(shared: &Shared) -> std::sync::MutexGuard<'_, Threads> {
    shared.0.lock().unwrap_or_else(|e| e.into_inner())
}

/// Ends with the listener thread: marks it ended and wakes `stop`.
struct ListenerExit(Shared, Counted);

impl Drop for ListenerExit {
    fn drop(&mut self) {
        lock(&self.0).listening = false;
        self.0 .1.notify_all();
    }
}

/// Ends with a connection thread: drops the connection's clone (so the
/// socket closes as soon as `serve` drops its own) and wakes `stop`.
struct ConnectionExit(Shared, u64, Counted);

impl Drop for ConnectionExit {
    fn drop(&mut self) {
        let mut t = lock(&self.0);
        t.open.remove(&self.1);
        t.live -= 1;
        drop(t);
        self.0 .1.notify_all();
    }
}

/// A fake's listener on its own port; `stop` ends its threads.
pub struct FakeServer {
    pub port: u16,
    shared: Shared,
    listener: Option<JoinHandle<()>>,
}

impl FakeServer {
    fn start(fake: Arc<Mutex<Fake>>) -> FakeServer {
        let listener = Listening::bind();
        let port = listener.0.local_addr().unwrap().port();
        let shared: Shared = Arc::default();
        lock(&shared).listening = true;
        let exit = ListenerExit(Arc::clone(&shared), Counted::new());
        let handle = std::thread::spawn(move || {
            let exit = exit;
            let shared = Arc::clone(&exit.0);
            loop {
                let accepted = listener.0.accept().and_then(|(stream, _)| {
                    let clone = stream.try_clone()?;
                    Ok((stream, clone))
                });
                let mut t = lock(&shared);
                if t.stop {
                    break;
                }
                let (stream, clone) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        // Kept for the message of a stop that does not end.
                        // The pause keeps an error that repeats (no file
                        // descriptors left, say) from spinning.
                        t.accept_errors += 1;
                        t.last_accept_error = Some(format!("{} ({:?})", e, e.kind()));
                        ACCEPT_ERRORS.fetch_add(1, Ordering::SeqCst);
                        drop(t);
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                };
                t.handles.retain(|h| !h.is_finished());
                let id = t.next;
                t.next += 1;
                t.open.insert(id, clone);
                t.live += 1;
                let exit = ConnectionExit(Arc::clone(&shared), id, Counted::new());
                let fake = Arc::clone(&fake);
                drop(t);
                let handle = std::thread::spawn(move || {
                    let _exit = exit;
                    serve(stream, fake);
                });
                lock(&shared).handles.push(handle);
            }
            // the listening socket closes before the thread counts as ended
            drop(listener);
            drop(exit);
        });
        FakeServer {
            port,
            shared,
            listener: Some(handle),
        }
    }

    /// What can explain a thread that has not ended: the errors of the wake
    /// connection and of accepts.
    fn errors(t: &Threads) -> String {
        let mut text = String::new();
        if let Some(e) = &t.wake_error {
            text.push_str(&format!(" (the wake connection failed: {})", e));
        }
        if t.accept_errors > 0 {
            text.push_str(&format!(
                " ({} failed accept(s), the last: {})",
                t.accept_errors,
                t.last_accept_error.as_deref().unwrap_or("?")
            ));
        }
        text
    }

    /// Ends the listener thread (and closes its socket), then shuts down
    /// every open connection and waits for its thread, all by `deadline`.
    /// If the deadline passes, returns what is still running and the errors
    /// that can explain it.
    fn stop(&mut self, deadline: Instant) -> Result<(), String> {
        lock(&self.shared).stop = true;
        // Wake the blocked `accept`: it sees `stop` and returns.
        let addr = (Ipv4Addr::LOCALHOST, self.port).into();
        let left = deadline.saturating_duration_since(Instant::now());
        if let Err(e) = TcpStream::connect_timeout(&addr, left.max(Duration::from_millis(1))) {
            lock(&self.shared).wake_error = Some(format!("{} ({:?})", e, e.kind()));
        }
        let (_, cv) = &*self.shared;
        let mut t = lock(&self.shared);
        while t.listening {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(format!(
                    "the listener of port {} has not ended{}",
                    self.port,
                    FakeServer::errors(&t)
                ));
            }
            t = cv
                .wait_timeout(t, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        // No connection is accepted any more.
        for stream in t.open.values() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        while t.live > 0 {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(format!(
                    "{} connection thread(s) of port {} have not ended{}",
                    t.live,
                    self.port,
                    FakeServer::errors(&t)
                ));
            }
            t = cv
                .wait_timeout(t, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        let handles = std::mem::take(&mut t.handles);
        drop(t);
        // Every thread is past its last blocking call: these joins return
        // at once. A thread that panicked has already said so.
        if let Some(listener) = self.listener.take() {
            let _ = listener.join();
        }
        for handle in handles {
            let _ = handle.join();
        }
        Ok(())
    }
}

/// Starts a fake on its own port.
fn spawn_fake() -> (Arc<Mutex<Fake>>, FakeServer) {
    let fake = Arc::new(Mutex::new(Fake {
        skew: SKEW,
        nvr_auth_ok: true,
        nonce: NONCE.to_string(),
        // the drop rule from the README
        rules: vec![Rule::new("raw", "cctv_ban", false)],
        ..Default::default()
    }));
    let server = FakeServer::start(Arc::clone(&fake));
    (fake, server)
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
    /// The fakes' servers, stopped when the harness is dropped.
    servers: Vec<FakeServer>,
}

impl Drop for Harness {
    /// Removes the directory and stops the fakes' servers: their threads
    /// end and are joined, their sockets close. A thread that has not ended
    /// within `STOP_TIMEOUT` fails the test (it is left running).
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
        // The engine's clients close their idle connections, which ends
        // the threads serving them. `stop` also shuts the connections down
        // from the server side, but on Windows that does not wake a thread
        // blocked reading.
        self.engine.readers.clear();
        self.engine.firewall = None;
        self.engine.notifier = None;
        sample_conntrack();
        let deadline = Instant::now() + STOP_TIMEOUT;
        let stuck: Vec<String> = self
            .servers
            .iter_mut()
            .filter_map(|server| server.stop(deadline).err())
            .collect();
        if !stuck.is_empty() {
            let text = format!(
                "a dropped harness could not stop its fakes within {:?}: {}{}",
                STOP_TIMEOUT,
                stuck.join("; "),
                conntrack_note()
            );
            if std::thread::panicking() {
                eprintln!("{}", text);
            } else {
                panic!("{}", text);
            }
        }
    }
}

impl Harness {
    /// A harness whose engine has not polled yet.
    pub fn build(opts: Opts) -> Harness {
        let (fake, server) = spawn_fake();
        let port = server.port;
        let mut servers = vec![server];
        let dir = std::env::temp_dir().join(format!(
            "hik-f2b-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // A setting may appear only once: `general` replaces the defaults
        // it sets.
        let set: Vec<String> = opts
            .general
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(key, _)| key.trim().to_string())
            .collect();
        let defaults: String = ["maxretry = 5", "findtime = 3600", "bantime = 86400"]
            .iter()
            .filter(|line| !set.iter().any(|key| line.starts_with(&format!("{} ", key))))
            .map(|line| format!("{}\n", line))
            .collect();
        let mut ini = format!(
            "[general]\n{}state_file = {}\n{}\n\
             [nvr:nvr1]\nurl = http://127.0.0.1:{port}\nuser = f2b\npassword = secret\n",
            defaults,
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
            let (fake2, server2) = spawn_fake();
            ini.push_str(&format!(
                "[nvr:nvr2]\nurl = http://127.0.0.1:{}\nuser = f2b\npassword = secret\n",
                server2.port
            ));
            servers.push(server2);
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
            servers,
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
        self.engine.state.ledger.failed_logins(ip(address))
    }

    pub fn since(&self, nvr: &str) -> String {
        device(self.engine.state.cursors[nvr].since())
    }

    /// Saves the state, loads it again and starts a new engine with it, as
    /// a restart of the daemon does.
    pub fn restart(&mut self) {
        let path = self.dir.join("state");
        self.engine.state.save(&path).unwrap();
        let restored = State::load(&path).unwrap();
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
