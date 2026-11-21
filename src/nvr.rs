//! Hikvision NVR client: digest authentication and ISAPI log search.

use crate::config::NvrCfg;
use crate::{http, util};
use std::borrow::Cow;
use std::collections::HashSet;
use std::net::IpAddr;

/// Per page. With `MAX_PAGES` and `MAX_EVENTS` this keeps one poll within a
/// few MiB however the device (or whoever answers in its place) behaves.
const MAX_BODY: u64 = 512 * 1024;
const PAGE_SIZE: usize = 100;
const MAX_PAGES: usize = 50;
const MAX_EVENTS: usize = MAX_PAGES * PAGE_SIZE;
/// Longest field text looked at while flattening an item.
const MAX_FIELD: usize = 256;
const MAX_USER: usize = 64;
const MAX_META: usize = 128;
/// Most `<` in one piece of XML handed to the parser (see `parse_xml`).
const MAX_MARKUP: usize = 256;

/// One log entry. `user` is whatever the remote party typed and must be
/// treated as hostile text.
#[derive(Clone, Debug)]
pub struct Event {
    pub nvr: String,
    pub ts: Option<i64>,
    pub ip: Option<IpAddr>,
    pub user: String,
    pub meta: String,
    pub key: String,
}

#[derive(Debug)]
pub enum NvrError {
    /// The NVR rejected our own login. Retrying quickly would trip its
    /// illegal-login lock, so the caller backs off.
    Auth(String),
    Other(String),
}

impl std::fmt::Display for NvrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NvrError::Auth(m) | NvrError::Other(m) => f.write_str(m),
        }
    }
}

/// The result of one log search.
#[derive(Debug, Default)]
pub struct Search {
    pub events: Vec<Event>,
    /// The search was not read to its end: paging stopped at the page or
    /// entry cap, or the NVR answered the same page twice (it ignores the
    /// search position). The window may hold more than was read.
    pub truncated: bool,
    /// Items that could not be parsed or were ambiguous, and were left out.
    pub skipped: usize,
    /// The ambiguous ones (up to `MAX_AMBIGUOUS`), for `--dump` only.
    pub ambiguous: Vec<Event>,
    /// Items on the first page that said more were to come: how many
    /// entries the NVR puts in one page. `None` if no page said so.
    pub page_size: Option<usize>,
}

/// Ambiguous items kept per search for `--dump`.
const MAX_AMBIGUOUS: usize = 100;

/// What a result page says about the pages after it
/// (`<responseStatusStrg>`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Paging {
    /// `OK` or `NO MATCHES`: this is the last page.
    Done,
    /// `MORE`: more pages follow.
    More,
    /// No status, more than one, or a value not known. Never taken as the
    /// last page: paging goes on until a page holds no entries.
    #[default]
    Unknown,
}

impl Paging {
    fn of(status: &str) -> Paging {
        let words: Vec<String> = status
            .split_ascii_whitespace()
            .map(|w| w.to_ascii_uppercase())
            .collect();
        match words.join(" ").as_str() {
            "MORE" => Paging::More,
            "OK" | "NO MATCHES" => Paging::Done,
            _ => Paging::Unknown,
        }
    }
}

/// One parsed result page.
#[derive(Debug, Default)]
pub struct Page {
    pub paging: Paging,
    /// Items on the page, including the ones that could not be parsed:
    /// this is what the next page's position must advance by.
    pub items: usize,
    pub events: Vec<Event>,
    /// Items left out: unparseable or ambiguous.
    pub skipped: usize,
    pub ambiguous: Vec<Event>,
}

impl Page {
    fn add(&mut self, item: Item) {
        match item {
            Item::Event(ev) => self.events.push(ev),
            Item::Ambiguous(ev) => {
                self.skipped += 1;
                self.ambiguous.push(ev);
            }
        }
    }
}

/// Replaces characters that XML 1.0 forbids even as character data (C0
/// controls other than tab, LF and CR; U+FFFE; U+FFFF). An NVR copies the
/// user name an attacker typed into its log verbatim, and one such
/// character would otherwise make that entry unparseable.
pub fn xml_safe(text: &str) -> Cow<'_, str> {
    let bad = |c: char| {
        (c < ' ' && c != '\t' && c != '\n' && c != '\r') || c == '\u{fffe}' || c == '\u{ffff}'
    };
    if text.chars().any(bad) {
        Cow::Owned(
            text.chars()
                .map(|c| if bad(c) { '\u{fffd}' } else { c })
                .collect(),
        )
    } else {
        Cow::Borrowed(text)
    }
}

/// Parses XML holding at most `MAX_MARKUP` `<`. roxmltree needs stack space
/// for each level of nesting, so without this bound markup typed as a user
/// name could exhaust the stack and abort the daemon. A real entry has about
/// 20, a time or error reply fewer.
fn parse_xml(text: &str) -> Result<roxmltree::Document<'_>, NvrError> {
    if text.matches('<').count() > MAX_MARKUP {
        return Err(NvrError::Other(
            "bad XML from NVR: too deeply nested or too long".to_string(),
        ));
    }
    roxmltree::Document::parse(text)
        .map_err(|e| NvrError::Other(format!("bad XML from NVR: {}", e)))
}

/// Escapes each `&` that does not start a reference XML allows without a
/// DTD (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`, or a character
/// reference to a character XML allows). Firmware that copies a user name
/// into its log without escaping it would otherwise make the entry
/// unparseable with a bare `&`, which an attacker could type to stay
/// uncounted. No `<` or `>` is added or removed, so the markup stays what it
/// was: the attacker could have typed `&amp;` just as well.
fn escape_bare_amps(text: &str) -> Cow<'_, str> {
    fn reference_len(rest: &str) -> Option<usize> {
        let end = rest.bytes().take(12).position(|b| b == b';')?;
        let name = &rest[1..end];
        let ok = match name.strip_prefix('#') {
            None => matches!(name, "amp" | "lt" | "gt" | "quot" | "apos"),
            Some(num) => {
                let value = match num.strip_prefix('x') {
                    Some(hex) if !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()) => {
                        u32::from_str_radix(hex, 16).ok()
                    }
                    Some(_) => None,
                    None if !num.is_empty() && num.chars().all(|c| c.is_ascii_digit()) => {
                        num.parse::<u32>().ok()
                    }
                    None => None,
                };
                value.and_then(char::from_u32).is_some_and(|c| {
                    matches!(c, '\t' | '\n' | '\r')
                        || (c >= ' ' && c != '\u{fffe}' && c != '\u{ffff}')
                })
            }
        };
        ok.then_some(end + 1)
    }
    if !text
        .match_indices('&')
        .any(|(i, _)| reference_len(&text[i..]).is_none())
    {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 16);
    let mut from = 0;
    for (i, _) in text.match_indices('&') {
        out.push_str(&text[from..i]);
        if reference_len(&text[i..]).is_some() {
            out.push('&');
        } else {
            out.push_str("&amp;");
        }
        from = i + 1;
    }
    out.push_str(&text[from..]);
    Cow::Owned(out)
}

/// The text of every `<responseStatusStrg>` element in raw markup, with or
/// without a namespace prefix and attributes; an empty or unclosed one gives
/// `""`.
fn status_values(text: &str) -> Vec<&str> {
    const NAME: &str = "responseStatusStrg";
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = text[from..].find('<') {
        let tag = from + i + 1;
        from = tag;
        let len = text[tag..]
            .find(|c: char| c.is_ascii_whitespace() || c == '>' || c == '/')
            .unwrap_or(text.len() - tag);
        let name = &text[tag..tag + len];
        if name.rsplit(':').next() != Some(NAME) || name.starts_with(['/', '!', '?']) {
            continue;
        }
        let Some(gt) = text[tag..].find('>') else {
            out.push("");
            break;
        };
        let body = tag + gt + 1;
        if text[..body - 1].ends_with('/') {
            out.push("");
            from = body;
            continue;
        }
        let close = format!("</{}", name);
        match text[body..].find(&close) {
            Some(end) => {
                out.push(&text[body..body + end]);
                from = body + end + close.len();
            }
            None => {
                out.push("");
                break;
            }
        }
    }
    out
}

/// Byte offset of the next `<searchMatchItem` start tag (not some longer
/// tag name that begins the same way).
fn next_item(text: &str) -> Option<usize> {
    const OPEN: &str = "<searchMatchItem";
    let mut from = 0;
    while let Some(i) = text[from..].find(OPEN) {
        let at = from + i;
        match text[at + OPEN.len()..].chars().next() {
            Some(c) if c == '>' || c.is_ascii_whitespace() => return Some(at),
            Some(_) => from = at + OPEN.len(),
            None => return None,
        }
    }
    None
}

/// Parses one `logSearch` reply. Each `<searchMatchItem>…</searchMatchItem>`
/// is cut out of the raw text and parsed on its own, so an entry that is
/// malformed, or holds markup typed as a user name, costs only itself: it
/// is counted as skipped and the rest of the page is read. The paging status
/// is taken only from the text between entries, and only if it occurs there
/// once: a user name that closes its entry early could put a second one
/// there.
pub fn parse_page(nvr: &str, raw: &str) -> Result<Page, NvrError> {
    const CLOSE: &str = "</searchMatchItem>";
    let safe = xml_safe(raw);
    let text = escape_bare_amps(&safe);
    let mut page = Page::default();
    let mut outside = String::new();
    let mut rest: &str = &text;
    while let Some(start) = next_item(rest) {
        outside.push_str(&rest[..start]);
        rest = &rest[start..];
        page.items += 1;
        let Some(end) = rest.find(CLOSE).map(|i| i + CLOSE.len()) else {
            // cut off: nothing after this can be an item either
            page.skipped += 1;
            rest = "";
            break;
        };
        // An item that holds another item's start tag (markup in a user
        // name) ends at the inner close tag and so never parses.
        match parse_xml(&rest[..end]) {
            Ok(doc) => page.add(parse_item(nvr, doc.root_element())),
            Err(_) => page.skipped += 1,
        }
        rest = &rest[end..];
    }
    outside.push_str(rest);
    let status = status_values(&outside);
    if let [one] = status.as_slice() {
        page.paging = Paging::of(one);
    } else if !status.is_empty() {
        page.paging = Paging::Unknown;
    } else if page.items == 0 {
        // not a result page: an error reply, or garbage
        let doc = parse_xml(&outside)?;
        if doc.root_element().tag_name().name() == "ResponseStatus" {
            let field = |tag: &str| {
                doc.descendants()
                    .find(|n| n.tag_name().name() == tag)
                    .and_then(|n| n.text())
                    .map(|t| util::sanitize(t, 60))
                    .unwrap_or_else(|| "?".to_string())
            };
            return Err(NvrError::Other(format!(
                "NVR refused log search: {} / {}",
                field("statusString"),
                field("subStatusCode")
            )));
        }
    }
    Ok(page)
}

/// Picks the challenge to answer from all `WWW-Authenticate` headers: the
/// Digest one if any. Without one the first header is returned, so that
/// `DigestAuth::challenge` refuses it (Basic is never answered).
pub fn pick_challenge<'a>(headers: &[&'a str]) -> &'a str {
    headers
        .iter()
        .find(|h| {
            h.trim()
                .get(..6)
                .is_some_and(|p| p.eq_ignore_ascii_case("digest"))
        })
        .or_else(|| headers.first())
        .copied()
        .unwrap_or("")
}

/// Splits `key=value, key="quoted, value"` pairs of an HTTP auth header.
pub fn parse_kv(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    loop {
        while matches!(chars.peek(), Some(c) if c.is_whitespace() || *c == ',') {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c == ',' {
                break;
            }
            key.push(c);
            chars.next();
        }
        if chars.peek() != Some(&'=') {
            continue;
        }
        chars.next();
        let mut value = String::new();
        if chars.peek() == Some(&'"') {
            chars.next();
            while let Some(c) = chars.next() {
                match c {
                    '\\' => {
                        if let Some(next) = chars.next() {
                            value.push(next);
                        }
                    }
                    '"' => break,
                    c => value.push(c),
                }
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c == ',' {
                    break;
                }
                value.push(c);
                chars.next();
            }
        }
        out.push((key.trim().to_ascii_lowercase(), value.trim().to_string()));
    }
    out
}

#[derive(Default)]
pub struct DigestAuth {
    user: String,
    pass: String,
    realm: String,
    nonce: String,
    opaque: String,
    qop: bool,
    nc: u32,
}

impl DigestAuth {
    pub fn new(user: &str, pass: &str) -> DigestAuth {
        DigestAuth {
            user: user.to_string(),
            pass: pass.to_string(),
            ..Default::default()
        }
    }

    pub fn has_nonce(&self) -> bool {
        !self.nonce.is_empty()
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn forget(&mut self) {
        self.nonce.clear();
    }

    /// Accepts a `WWW-Authenticate` challenge. Only Digest/MD5 is accepted:
    /// a Basic challenge is refused, so the password is never sent in a
    /// reversible form even if something in the path asks for it.
    /// Returns whether the server marked our previous nonce as stale.
    pub fn challenge(&mut self, header: &str) -> Result<bool, String> {
        let header = header.trim();
        let rest = match header.get(..6) {
            Some(p) if p.eq_ignore_ascii_case("digest") => header.get(6..).unwrap_or(""),
            _ => return Err("the NVR did not offer Digest authentication".to_string()),
        };
        let clean =
            |v: &str| v.len() <= 512 && !v.chars().any(|c| c == '"' || c == '\\' || c.is_control());
        let (mut realm, mut nonce, mut opaque) = (String::new(), String::new(), String::new());
        let (mut qop, mut has_qop, mut stale) = (false, false, false);
        for (key, value) in parse_kv(rest) {
            if !clean(&value) {
                return Err("malformed Digest challenge".to_string());
            }
            match key.as_str() {
                "realm" => realm = value,
                "nonce" => nonce = value,
                "opaque" => opaque = value,
                "stale" => stale = value.eq_ignore_ascii_case("true"),
                "algorithm" => {
                    if !value.eq_ignore_ascii_case("MD5") {
                        return Err(format!(
                            "unsupported Digest algorithm {}",
                            util::sanitize(&value, 20)
                        ));
                    }
                }
                "qop" => {
                    has_qop = true;
                    qop = value
                        .split(',')
                        .any(|q| q.trim().eq_ignore_ascii_case("auth"));
                }
                _ => {}
            }
        }
        if nonce.is_empty() || (has_qop && !qop) {
            return Err("unsupported Digest challenge".to_string());
        }
        self.realm = realm;
        self.nonce = nonce;
        self.opaque = opaque;
        self.qop = qop;
        self.nc = 0;
        Ok(stale)
    }

    pub fn header(&mut self, method: &str, uri: &str) -> String {
        let ha1 = util::md5_hex(&format!("{}:{}:{}", self.user, self.realm, self.pass));
        let ha2 = util::md5_hex(&format!("{}:{}", method, uri));
        let mut out = format!(
            "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", algorithm=MD5",
            self.user, self.realm, self.nonce, uri
        );
        if self.qop {
            self.nc = self.nc.wrapping_add(1);
            let nc = format!("{:08x}", self.nc);
            let cnonce = util::random_hex();
            let response = util::md5_hex(&format!(
                "{}:{}:{}:{}:auth:{}",
                ha1, self.nonce, nc, cnonce, ha2
            ));
            out.push_str(&format!(
                ", response=\"{}\", qop=auth, nc={}, cnonce=\"{}\"",
                response, nc, cnonce
            ));
        } else {
            let response = util::md5_hex(&format!("{}:{}:{}", ha1, self.nonce, ha2));
            out.push_str(&format!(", response=\"{}\"", response));
        }
        if !self.opaque.is_empty() {
            out.push_str(&format!(", opaque=\"{}\"", self.opaque));
        }
        out
    }
}

pub struct Nvr {
    pub name: String,
    pub url: String,
    agent: ureq::Agent,
    auth: DigestAuth,
    /// Host time before which this NVR is not contacted (after a rejected login).
    pub retry_after: u64,
    /// Polls in a row that failed for a reason other than our login being
    /// rejected (kept in memory only).
    pub failed_polls: u32,
}

impl Nvr {
    pub fn new(cfg: &NvrCfg) -> Result<Nvr, String> {
        Ok(Nvr {
            name: cfg.name.clone(),
            url: cfg.url.clone(),
            agent: http::agent(&cfg.url, cfg.ca_file.as_deref(), http::DEFAULT_TIMEOUT)
                .map_err(|e| format!("nvr {}: {}", cfg.name, e))?,
            auth: DigestAuth::new(&cfg.user, &cfg.password),
            retry_after: 0,
            failed_polls: 0,
        })
    }

    /// One ISAPI request with Digest authentication. At most three requests
    /// go out: one without credentials to get a challenge (only when there
    /// is no nonce yet), one with credentials, and one more if the reply
    /// shows that our nonce had expired. Anything else that refuses our
    /// credentials is an authentication failure at once, because repeated
    /// attempts would trip the NVR's own illegal-login lock.
    fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<String, NvrError> {
        let mut renewed = false;
        loop {
            let url = format!("{}{}", self.url, path);
            let mut req = self.agent.request(method, &url);
            let sent_credentials = self.auth.has_nonce();
            let used_nonce = self.auth.nonce().to_string();
            if sent_credentials {
                let header = self.auth.header(method, path);
                req = req.set("Authorization", &header);
            }
            let result = match body {
                Some(b) => req
                    .set("Content-Type", "application/xml; charset=UTF-8")
                    .send_string(b),
                None => req.call(),
            };
            match result {
                Ok(resp) => {
                    if resp.status() != 200 {
                        return Err(NvrError::Other(format!(
                            "unexpected HTTP {}",
                            resp.status()
                        )));
                    }
                    return http::read_body(resp, MAX_BODY).map_err(NvrError::Other);
                }
                Err(ureq::Error::Status(401, resp)) => {
                    // A device may offer Basic next to Digest; only the
                    // Digest challenge is ever answered.
                    let headers = resp.all("WWW-Authenticate");
                    let header = pick_challenge(&headers).to_string();
                    let stale = match self.auth.challenge(&header) {
                        Ok(stale) => stale,
                        Err(e) => {
                            self.auth.forget();
                            return Err(NvrError::Auth(e));
                        }
                    };
                    if sent_credentials {
                        // Some firmware rotates its nonce without setting
                        // stale=true. A different nonce than the one just
                        // used means ours expired, not that the password is
                        // wrong; that deserves exactly one more try.
                        let expired = stale || self.auth.nonce() != used_nonce;
                        if !expired || renewed {
                            self.auth.forget();
                            return Err(NvrError::Auth("HTTP 401".to_string()));
                        }
                        renewed = true;
                    }
                }
                Err(ureq::Error::Status(403, _)) => {
                    return Err(NvrError::Auth("HTTP 403".to_string()))
                }
                Err(ureq::Error::Status(code, _)) => {
                    return Err(NvrError::Other(format!("HTTP {}", code)))
                }
                Err(e) => return Err(NvrError::Other(util::sanitize(&e.to_string(), 200))),
            }
        }
    }

    /// The device's own wall-clock time.
    pub fn now(&mut self) -> Result<i64, NvrError> {
        let raw = self.request("GET", "/ISAPI/System/time", None)?;
        let raw = xml_safe(&raw);
        let doc = parse_xml(&raw)?;
        let text = doc
            .descendants()
            .find(|n| n.tag_name().name() == "localTime")
            .and_then(|n| n.text())
            .ok_or_else(|| NvrError::Other("device time not found in reply".to_string()))?;
        // A clock before 1970 (after a reset of its battery-backed clock)
        // cannot be kept in the state file, so it is refused like a reply
        // without a time: the NVR is not read until its clock is set.
        util::parse_ts(text).ok_or_else(|| {
            NvrError::Other(format!(
                "device time {:?} cannot be used: not a date, or before 1970",
                util::sanitize(text.trim(), 40)
            ))
        })
    }

    /// All log entries of type `meta_id` between `start` and `end`, up to
    /// `MAX_PAGES` pages / `MAX_EVENTS` entries (`truncated` says whether
    /// the cap was hit).
    pub fn search(
        &mut self,
        start: i64,
        end: i64,
        meta_id: &str,
        raw_sink: Option<&mut Vec<String>>,
    ) -> Result<Search, NvrError> {
        self.search_pages(start, end, meta_id, MAX_PAGES, raw_sink)
    }

    /// As `search`, but at most `pages` pages (at most `MAX_PAGES`), for a
    /// quick look such as `--check`. Stopping early is not worth a warning.
    pub fn sample(
        &mut self,
        start: i64,
        end: i64,
        meta_id: &str,
        pages: usize,
    ) -> Result<Search, NvrError> {
        self.search_pages(start, end, meta_id, pages.clamp(1, MAX_PAGES), None)
    }

    fn search_pages(
        &mut self,
        start: i64,
        end: i64,
        meta_id: &str,
        max_pages: usize,
        mut raw_sink: Option<&mut Vec<String>>,
    ) -> Result<Search, NvrError> {
        let mut out = Search {
            truncated: true, // until the last page has been seen
            ..Search::default()
        };
        let mut position = 0usize;
        let mut previous: Option<String> = None;
        let mut ambiguous = 0usize;
        // the NVR answered the same page twice
        let mut stuck = false;
        // a page with entries had no paging status hik-f2b knows
        let mut unknown_status = false;
        let id = util::random_hex();
        let search_id = format!("{}-0000-4000-8000-{}0000", &id[..8], &id[8..16]);
        for _ in 0..max_pages {
            let body = format!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?><CMSearchDescription>\
                 <searchID>{}</searchID><metaId>{}</metaId><timeSpanList><timeSpan>\
                 <startTime>{}</startTime><endTime>{}</endTime></timeSpan></timeSpanList>\
                 <maxResults>{}</maxResults><searchResultPostion>{}</searchResultPostion>\
                 </CMSearchDescription>",
                search_id,
                meta_id,
                util::fmt_ts(start),
                util::fmt_ts(end),
                PAGE_SIZE,
                position
            );
            let raw = self.request("POST", "/ISAPI/ContentMgmt/logSearch", Some(&body))?;
            if previous.as_deref() == Some(raw.as_str()) {
                // Firmware that ignores searchResultPostion answers every
                // page with the first one; reading on would count the same
                // entries again on each page. The search was not read to
                // its end, so it stays truncated: the caller reads the rest
                // as it does after a search that reached the cap.
                crate::warn!(
                    "{}: the NVR returned the same result page twice; it seems to ignore the \
                     search position, so this search stops after that page",
                    self.name
                );
                stuck = true;
                break;
            }
            let page = parse_page(&self.name, &raw)?;
            out.skipped += page.skipped;
            out.events.extend(page.events);
            ambiguous += page.ambiguous.len();
            let room = MAX_AMBIGUOUS.saturating_sub(out.ambiguous.len());
            out.ambiguous.extend(page.ambiguous.into_iter().take(room));
            if let Some(sink) = raw_sink.as_mut() {
                sink.push(raw.clone());
            }
            if out.events.len() > MAX_EVENTS {
                // a device that ignores maxResults could otherwise fill
                // memory with 50 huge pages; what is left out was not read
                out.events.truncate(MAX_EVENTS);
                break;
            }
            // A page without entries ends the search whatever it says: the
            // position would not move on.
            if page.items == 0 || page.paging == Paging::Done {
                out.truncated = false;
                break;
            }
            if page.paging == Paging::Unknown {
                // read on: only a page without entries ends the search
                unknown_status = true;
            } else if out.page_size.is_none() {
                out.page_size = Some(page.items);
            }
            if out.events.len() == MAX_EVENTS {
                break;
            }
            position += page.items;
            previous = Some(raw);
        }
        if unknown_status {
            crate::warn!(
                "{}: a result page had no paging status, more than one, or one that is not \
                 known (OK, MORE, NO MATCHES); such a page is not taken for the last one, \
                 and the search reads on until a page holds no entries",
                self.name
            );
        }
        if out.truncated && !stuck && max_pages == MAX_PAGES {
            crate::warn!(
                "{}: more than {} log entries in the search window, this search stops there",
                self.name,
                out.events.len()
            );
        }
        if out.skipped > 0 {
            crate::warn!(
                "{}: {} log entr{} could not be parsed and {} skipped{}",
                self.name,
                out.skipped,
                if out.skipped == 1 { "y" } else { "ies" },
                if out.skipped == 1 { "was" } else { "were" },
                if ambiguous > 0 {
                    format!(
                        " ({} with a repeated user, address, time or type field: probably \
                         markup typed as a user name)",
                        ambiguous
                    )
                } else {
                    String::new()
                }
            );
        }
        Ok(out)
    }
}

/// An address field's value. `::ffff:a.b.c.d` (how a dual-stack listener
/// reports an IPv4 client) is the IPv4 address it wraps; `::` and `0.0.0.0`
/// (no remote address) are none.
fn parse_addr(text: &str) -> Option<IpAddr> {
    let addr = match text.parse::<IpAddr>().ok()? {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    Some(addr).filter(|a| !a.is_unspecified())
}

/// Text the remote party chose (the login name). Never a source of an
/// address or a time.
fn attacker_typed(key: &str) -> bool {
    key.contains("user")
}

/// Field names that may hold the remote address.
fn address_key(key: &str) -> bool {
    !attacker_typed(key)
        && (key.starts_with("ip")
            || key.ends_with("address")
            || key.ends_with("addr")
            || key.contains("host"))
}

const TIME_KEYS: [&str; 4] = ["startdatetime", "starttime", "datetime", "time"];

/// Fields that decide whether and against whom an entry counts. Each may
/// appear only once in an item (see `parse_item`).
fn decisive_key(key: &str) -> bool {
    attacker_typed(key) || address_key(key) || TIME_KEYS.contains(&key) || key == "metaid"
}

/// One flattened `<searchMatchItem>`.
#[derive(Debug)]
pub enum Item {
    Event(Event),
    /// A decisive field appears more than once, which a real device never
    /// writes: most likely markup injected through the user name. Never
    /// counted; the event (without an address) is kept for `--dump` only.
    Ambiguous(Event),
}

/// All text below `node`, concatenated and trimmed.
fn flat_text(node: roxmltree::Node) -> String {
    let text: String = node
        .descendants()
        .filter(|n| n.is_text())
        .filter_map(|n| n.text())
        .collect();
    text.trim().to_string()
}

/// Flattens one `<searchMatchItem>`. Field names differ between firmware
/// versions, so time, address and user are located by field name.
///
/// Some firmware copies the login name into its log without escaping `<`,
/// so an attacker can inject elements. Two rules keep that harmless:
/// anything below a user-name element is the attacker's text and never a
/// field (nested injection), and an item in which a decisive field occurs
/// twice is `Ambiguous` (injection that closes the user-name element first).
pub fn parse_item(nvr: &str, item: roxmltree::Node) -> Item {
    let mut fields: Vec<(String, String)> = Vec::new();
    let mut decisive: HashSet<String> = HashSet::new();
    let mut ambiguous = false;
    // (is it exactly <userName>, flattened text) of each user-name element
    let mut users: Vec<(bool, String)> = Vec::new();
    for node in item.descendants().skip(1).filter(|n| n.is_element()) {
        let inside_user = node
            .ancestors()
            .skip(1)
            .take_while(|a| *a != item)
            .any(|a| attacker_typed(&a.tag_name().name().to_ascii_lowercase()));
        if inside_user {
            continue;
        }
        let key = node.tag_name().name().to_ascii_lowercase();
        if decisive_key(&key) && !decisive.insert(key.clone()) {
            ambiguous = true;
        }
        if attacker_typed(&key) {
            users.push((key == "username", flat_text(node)));
            continue;
        }
        if node.children().any(|c| c.is_element()) {
            continue;
        }
        let text = node.text().unwrap_or("").trim();
        if text.is_empty() {
            continue;
        }
        if fields.len() < 64 && !fields.iter().any(|(k, _)| *k == key) {
            fields.push((key, text.chars().take(MAX_FIELD).collect()));
        }
    }
    let get = |name: &str| {
        fields
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };

    let meta: String = get("metaid").unwrap_or("").chars().take(MAX_META).collect();

    // user-name fields never reach `fields`, so this fallback cannot read
    // a time the attacker typed
    let ts = TIME_KEYS
        .iter()
        .find_map(|k| get(k).and_then(util::parse_ts))
        .or_else(|| fields.iter().find_map(|(_, v)| util::parse_ts(v)));

    // Real devices put the remote address in <ipAddress> ("::" when there
    // is none). The address is taken from such a field only: free text can
    // mention other addresses (a camera's), and the user name is whatever
    // the attacker typed, so with an empty address field a scan of the text
    // would let anyone get a victim's address banned.
    let ip = if ambiguous {
        None
    } else {
        fields
            .iter()
            .filter(|(k, _)| address_key(k))
            .find_map(|(_, v)| parse_addr(v))
    };

    // <userName> if it has text, else the first other user-name field with
    // text; injected markup inside it is kept as text
    let user: String = users
        .iter()
        .filter(|(_, text)| !text.is_empty())
        .min_by_key(|(exact, _)| !exact)
        .map(|(_, text)| text.as_str())
        .unwrap_or("")
        .chars()
        .take(MAX_USER)
        .collect();

    let key = util::md5_hex(&format!(
        "{:?}|{:?}|{}|{}|{}",
        ts,
        ip,
        user,
        meta,
        get("localid").unwrap_or("")
    ));
    let event = Event {
        nvr: nvr.to_string(),
        ts,
        ip,
        user,
        meta,
        key,
    };
    if ambiguous {
        Item::Ambiguous(event)
    } else {
        Item::Event(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(xml: &str) -> Item {
        let doc = roxmltree::Document::parse(xml).unwrap();
        parse_item("n", doc.root_element())
    }

    fn item(xml: &str) -> Event {
        match parse(xml) {
            Item::Event(ev) => ev,
            Item::Ambiguous(ev) => panic!("ambiguous: {:?}", ev),
        }
    }

    fn failed_login(user: &str) -> String {
        format!(
            "<searchMatchItem xmlns=\"http://www.hikvision.com/ver20/XMLSchema\"><logDescriptor>\
             <metaId>log.hikvision.com/Exception/illlegealAccess</metaId>\
             <StartDateTime>2026-01-10T10:00:00Z</StartDateTime>\
             <localID>D1</localID><localId>D1</localId><paraType></paraType>\
             <userName>{}</userName><ipAddress>198.51.100.7</ipAddress>\
             </logDescriptor></searchMatchItem>",
            user
        )
    }

    #[test]
    fn real_format_with_both_local_ids_is_not_ambiguous() {
        // DS-7732NXI-K4 writes <localID> and <localId> with the same value
        let ev = item(&failed_login("admin"));
        assert_eq!(ev.ip, Some("198.51.100.7".parse().unwrap()));
        assert_eq!(ev.user, "admin");
        assert!(ev.ts.is_some());
    }

    #[test]
    fn nested_markup_in_user_name_is_text() {
        let ev = item(&failed_login(
            "a<ipAddress>203.0.113.9</ipAddress><StartDateTime>2020-01-01T00:00:00Z\
             </StartDateTime>",
        ));
        assert_eq!(ev.ip, Some("198.51.100.7".parse().unwrap()));
        assert_eq!(ev.ts.map(util::fmt_ts).unwrap(), "2026-01-10T10:00:00Z");
        assert_eq!(ev.user, "a203.0.113.92020-01-01T00:00:00Z");
        // the whole injected text, cut to MAX_USER
        let long = format!("<x>{}</x>", "y".repeat(100));
        assert_eq!(item(&failed_login(&long)).user.len(), MAX_USER);
    }

    #[test]
    fn repeated_decisive_fields_make_an_item_ambiguous() {
        // the name closes <userName>, adds an address and reopens <userName>
        let sibling = failed_login("a</userName><ipAddress>203.0.113.9</ipAddress><userName>b");
        let ambiguous = [
            sibling.as_str(),
            "<searchMatchItem><metaId>log.x/illegalLogin</metaId><StartDateTime>\
             2026-01-10T10:00:00Z</StartDateTime><ipAddress>203.0.113.9</ipAddress>\
             <ipAddress>198.51.100.7</ipAddress></searchMatchItem>",
            "<searchMatchItem><remoteHost>203.0.113.9</remoteHost>\
             <remoteHost>198.51.100.7</remoteHost></searchMatchItem>",
            "<searchMatchItem><StartDateTime>2026-01-10T10:00:00Z</StartDateTime>\
             <StartDateTime>2020-01-10T10:00:00Z</StartDateTime>\
             <ipAddress>198.51.100.7</ipAddress></searchMatchItem>",
            "<searchMatchItem><metaId>a</metaId><metaId>b</metaId>\
             <ipAddress>198.51.100.7</ipAddress></searchMatchItem>",
            "<searchMatchItem><userName>a</userName><userName/>\
             <ipAddress>198.51.100.7</ipAddress></searchMatchItem>",
        ];
        for xml in ambiguous {
            match parse(xml) {
                Item::Ambiguous(ev) => assert_eq!(ev.ip, None, "{}", xml),
                Item::Event(ev) => panic!("not ambiguous: {} -> {:?}", xml, ev),
            }
        }
        // repeated fields that decide nothing are fine
        let ev = item(
            "<searchMatchItem><localID>D1</localID><localId>D1</localId><paraType/>\
             <paraType/><ipAddress>198.51.100.7</ipAddress></searchMatchItem>",
        );
        assert_eq!(ev.ip, Some("198.51.100.7".parse().unwrap()));
    }

    #[test]
    fn injection_is_left_out_of_pages() {
        let sibling = failed_login("a</userName><ipAddress>203.0.113.9</ipAddress><userName>b");
        let nested = failed_login("a<ipAddress>203.0.113.9</ipAddress>");
        let forged_item = failed_login(
            "a<searchMatchItem><metaId>log.hikvision.com/Exception/illlegealAccess</metaId>\
             <StartDateTime>2026-01-10T10:00:00Z</StartDateTime>\
             <ipAddress>203.0.113.9</ipAddress></searchMatchItem>",
        );
        let status = failed_login("<responseStatusStrg>MORE</responseStatusStrg>");
        let body = format!("{}{}{}{}", sibling, nested, forged_item, status);
        let whole = format!(
            "<?xml version=\"1.0\"?><CMSearchResult><responseStatusStrg>OK\
             </responseStatusStrg><matchList>{}</matchList></CMSearchResult>",
            body
        );
        // the same with a bare & that breaks the document as a whole
        let broken = format!(
            "{}{}",
            whole.replace("</matchList>", ""),
            page_item("a & b")
        );
        for (raw, items, counted) in [(whole, 4, 2), (broken, 5, 3)] {
            let page = parse_page("n", &raw).unwrap();
            // counted: nested, status and (read as text) the bare &;
            // skipped: sibling (ambiguous) and the forged item (does not
            // parse)
            assert_eq!(
                (page.items, page.events.len(), page.skipped),
                (items, counted, 2),
                "{:?}",
                page
            );
            assert_eq!(page.ambiguous.len(), 1);
            assert_eq!(
                page.paging,
                Paging::Done,
                "status injected into an item is ignored"
            );
            for ev in &page.events {
                assert_eq!(ev.ip, Some("198.51.100.7".parse().unwrap()), "{:?}", ev);
            }
            assert!(page.events.iter().any(|ev| ev.user.starts_with("a203")));
        }
    }

    #[test]
    fn deep_or_long_markup_costs_only_its_item() {
        // in a test thread's small stack, nesting this deep would overflow it
        let nest = |n: usize| format!("{}x{}", "<u>".repeat(n), "</u>".repeat(n));
        let many: String = (0..20_000).map(|i| format!("<ip{}/>", i)).collect();
        let raw = format!(
            "{}{}{}{}{}</matchList></CMSearchResult>",
            PAGE_HEAD,
            page_item(&nest(100_000)),
            page_item(&many),
            page_item(&nest(100)),
            page_item("admin")
        );
        let page = parse_page("n", &raw).unwrap();
        assert_eq!((page.items, page.events.len(), page.skipped), (4, 2, 2));
        assert_eq!(page.events[0].user, "x");
        assert_eq!(page.events[1].user, "admin");
        assert!(parse_page("n", &nest(100_000)).is_err());
    }

    #[test]
    fn auth_header_pairs() {
        let kv = parse_kv(r#" realm="a, b", domain="/", qop="auth", nonce=abc=, stale="FALSE""#);
        assert_eq!(kv[0], ("realm".to_string(), "a, b".to_string()));
        assert_eq!(kv[2], ("qop".to_string(), "auth".to_string()));
        assert_eq!(kv[3], ("nonce".to_string(), "abc=".to_string()));
        assert_eq!(kv.len(), 5);
        assert!(parse_kv(",,, =x, novalue, ").len() <= 1);
    }

    #[test]
    fn digest_challenges() {
        let mut d = DigestAuth::new("Mufasa", "Circle Of Life");
        // RFC 2617 example
        let stale = d
            .challenge(r#"Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41""#)
            .unwrap();
        assert!(!stale);
        let h = d.header("GET", "/dir/index.html");
        assert!(
            h.contains(r#"username="Mufasa""#)
                && h.contains("qop=auth")
                && h.contains("nc=00000001")
        );

        let mut d = DigestAuth::new("u", "p");
        assert!(
            d.challenge(r#"Basic realm="x""#).is_err(),
            "Basic must be refused"
        );
        assert!(d
            .challenge(r#"Digest realm="x", nonce="n", algorithm=SHA-512"#)
            .is_err());
        assert!(
            d.challenge("Digest realm=\"x\", nonce=\"a\\\"b\"").is_err(),
            "quote inside a value"
        );
        assert!(d.challenge(r#"Digest realm="x""#).is_err(), "no nonce");
        assert!(d
            .challenge(r#"Digest realm="x", nonce="n", stale=TRUE"#)
            .unwrap());
        // legacy challenge without qop (RFC 2069 form)
        let h = d.header("GET", "/");
        assert!(!h.contains("qop") && h.contains("response="));
    }

    #[test]
    fn real_log_formats() {
        let filter =
            regex_lite::Regex::new(&format!("(?i){}", crate::config::DEFAULT_FILTER)).unwrap();
        // failed login as logged by a DS-7616NI-Q1, firmware V4.72
        let failed = item(
            "<searchMatchItem xmlns=\"http://www.hikvision.com/ver20/XMLSchema\"><logDescriptor>\
             <metaId>log.hikvision.com/Exception/illlegealAccess</metaId>\
             <StartDateTime>2026-01-10T10:00:00Z</StartDateTime><paraType></paraType>\
             <userName>admin</userName><ipAddress>198.51.100.7</ipAddress>\
             </logDescriptor></searchMatchItem>",
        );
        assert_eq!(failed.ip, Some("198.51.100.7".parse().unwrap()));
        assert_eq!(failed.user, "admin");
        assert_eq!(failed.ts.map(util::fmt_ts).unwrap(), "2026-01-10T10:00:00Z");
        assert!(filter.is_match(&failed.meta));
        // camera event as logged by a DS-7732NXI-K4, firmware V4.83: the only
        // address is a camera's, inside free text, and must not be used
        let camera = item(
            "<searchMatchItem><logDescriptor>\
             <metaId>log.hikvision.com/Exception/videoLost/30</metaId>\
             <StartDateTime>2026-01-10T10:00:00Z</StartDateTime>\
             <localID>D30</localID><localId>D30</localId><paraType></paraType>\
             <userName></userName><ipAddress>::</ipAddress>\
             <additionInformation>Camera D30\nIP address: 192.0.2.40\nPort: 8000</additionInformation>\
             </logDescriptor></searchMatchItem>",
        );
        assert_eq!(camera.ip, None);
        assert!(!filter.is_match(&camera.meta));
    }

    #[test]
    fn other_field_names_and_free_text() {
        let ev = item(
            "<searchMatchItem><logDescriptor>\
             <metaId>log.std-cgi.com/Exception/illegalLogin</metaId>\
             <time>2026-01-10T10:00:00+02:00</time>\
             <remoteHostAddr>198.51.100.7</remoteHostAddr><netUser>admin</netUser>\
             </logDescriptor></searchMatchItem>",
        );
        assert_eq!(ev.ip, Some("198.51.100.7".parse().unwrap()));
        assert_eq!(ev.user, "admin");
        // free text is never searched for an address
        let ev = item(
            "<searchMatchItem><metaId>log.std-cgi.com/Exception/illegalLogin</metaId>\
             <StartDateTime>2026-01-10T10:00:00Z</StartDateTime>\
             <description>Remote host 198.51.100.7, 0.0.0.0</description></searchMatchItem>",
        );
        assert_eq!(ev.ip, None);
        // not an address at all
        let ev =
            item("<searchMatchItem><ipAddress>999.1.1.1; rm -rf</ipAddress></searchMatchItem>");
        assert_eq!(ev.ip, None);
    }

    #[test]
    fn attacker_text_is_not_an_address_or_time() {
        let ev = item(
            "<searchMatchItem><logDescriptor>\
             <metaId>log.hikvision.com/Exception/illlegealAccess</metaId>\
             <userName>203.0.113.99 2026-01-10T10:00:00</userName><ipAddress></ipAddress>\
             </logDescriptor></searchMatchItem>",
        );
        assert_eq!(ev.ip, None);
        assert_eq!(ev.ts, None);
        assert_eq!(ev.user, "203.0.113.99 2026-01-10T10:00:00");
        // a long user name and metaId are cut
        let long = "u".repeat(300);
        let ev = item(&format!(
            "<searchMatchItem><metaId>{}</metaId><userName>{}</userName></searchMatchItem>",
            long, long
        ));
        assert_eq!(ev.user.len(), MAX_USER);
        assert_eq!(ev.meta.len(), MAX_META);
    }

    #[test]
    fn mapped_ipv6_is_ipv4() {
        let ev =
            item("<searchMatchItem><ipAddress>::ffff:198.51.100.7</ipAddress></searchMatchItem>");
        assert_eq!(ev.ip, Some("198.51.100.7".parse().unwrap()));
        let ev = item("<searchMatchItem><ipAddress>2001:db8::7</ipAddress></searchMatchItem>");
        assert_eq!(ev.ip, Some("2001:db8::7".parse().unwrap()));
        let ev = item("<searchMatchItem><ipAddress>::ffff:0.0.0.0</ipAddress></searchMatchItem>");
        assert_eq!(ev.ip, None);
    }

    const PAGE_HEAD: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<CMSearchResult \
         xmlns=\"http://www.hikvision.com/ver20/XMLSchema\"><responseStatusStrg>MORE\
         </responseStatusStrg><matchList>";

    fn page_item(user: &str) -> String {
        format!(
            "<searchMatchItem><logDescriptor><metaId>log.hikvision.com/Exception/illlegealAccess\
             </metaId><StartDateTime>2026-01-10T10:00:00Z</StartDateTime><userName>{}</userName>\
             <ipAddress>198.51.100.7</ipAddress></logDescriptor></searchMatchItem>",
            user
        )
    }

    #[test]
    fn forbidden_characters_are_replaced() {
        assert!(matches!(xml_safe("a\tb\r\nc\u{fffd}"), Cow::Borrowed(_)));
        assert_eq!(
            xml_safe("a\u{1}b\u{fffe}\u{ffff}\u{1f}"),
            "a\u{fffd}b\u{fffd}\u{fffd}\u{fffd}"
        );
        let raw = format!(
            "{}{}{}</matchList></CMSearchResult>",
            PAGE_HEAD,
            page_item("ad\u{1}min"),
            page_item("admin")
        );
        let page = parse_page("n", &raw).unwrap();
        assert_eq!((page.items, page.events.len(), page.skipped), (2, 2, 0));
        assert_eq!(page.paging, Paging::More);
        assert_eq!(page.events[0].user, "ad\u{fffd}min");
    }

    #[test]
    fn broken_page_is_salvaged_item_by_item() {
        let raw = format!(
            "{}{}{}{}{}</matchList></CMSearchResult>",
            PAGE_HEAD,
            page_item("a & b"),
            page_item("bad&#1;ref"),
            page_item("a<b"),
            page_item("admin")
        );
        let page = parse_page("n", &raw).unwrap();
        assert_eq!((page.items, page.events.len(), page.skipped), (4, 3, 1));
        // a bare & and a reference XML forbids are read as text
        let users: Vec<&str> = page.events.iter().map(|e| e.user.as_str()).collect();
        assert_eq!(users, ["a & b", "bad&#1;ref", "admin"]);
        assert_eq!(page.paging, Paging::More, "status is still read");
        // a cut-off last item counts as an item but is skipped
        let cut = format!(
            "{}{}{}",
            PAGE_HEAD,
            page_item("admin"),
            &page_item("x")[..40]
        );
        let page = parse_page("n", &cut).unwrap();
        assert_eq!((page.items, page.events.len(), page.skipped), (2, 1, 1));
        // nothing recognisable at all
        assert!(parse_page("n", "<<< garbage").is_err());
        assert!(parse_page("n", "").is_err());
        // an error reply, and a well-formed page without status or entries
        let refused = parse_page(
            "n",
            "<ResponseStatus><statusString>Invalid Operation</statusString>\
             <subStatusCode>badXmlFormat</subStatusCode></ResponseStatus>",
        );
        assert_eq!(
            refused.unwrap_err().to_string(),
            "NVR refused log search: Invalid Operation / badXmlFormat"
        );
        let empty = parse_page("n", "<CMSearchResult><matchList/></CMSearchResult>").unwrap();
        assert_eq!((empty.items, empty.paging), (0, Paging::Unknown));
        // a longer tag name is not an item
        assert!(next_item("<searchMatchItemList>").is_none());
    }

    #[test]
    fn challenge_selection() {
        assert_eq!(
            pick_challenge(&["Basic realm=\"x\"", "Digest realm=\"x\", nonce=\"n\""]),
            "Digest realm=\"x\", nonce=\"n\""
        );
        assert_eq!(pick_challenge(&["Basic realm=\"x\""]), "Basic realm=\"x\"");
        assert_eq!(pick_challenge(&[]), "");
        let mut d = DigestAuth::new("u", "p");
        assert!(d.challenge(pick_challenge(&["Basic realm=\"x\""])).is_err());
    }

    #[test]
    fn paging_status_is_matched_tolerantly() {
        let page = |head: &str, items: usize| {
            let body: String = (0..items).map(|_| page_item("admin")).collect();
            parse_page(
                "n",
                &format!(
                    "<?xml version=\"1.0\"?><CMSearchResult>{}<matchList>{}</matchList>\
                     </CMSearchResult>",
                    head, body
                ),
            )
            .unwrap()
            .paging
        };
        for (head, paging) in [
            (
                "<responseStatusStrg>MORE</responseStatusStrg>",
                Paging::More,
            ),
            (
                "<responseStatusStrg> more\n</responseStatusStrg>",
                Paging::More,
            ),
            (
                "<hik:responseStatusStrg xmlns:hik=\"urn:x\">MORE</hik:responseStatusStrg>",
                Paging::More,
            ),
            (
                "<responseStatusStrg type=\"s\" >MORE</responseStatusStrg >",
                Paging::More,
            ),
            ("<responseStatusStrg>OK</responseStatusStrg>", Paging::Done),
            (
                "<responseStatusStrg>NO  MATCHES</responseStatusStrg>",
                Paging::Done,
            ),
            // not known, empty, missing or twice: never the last page
            (
                "<responseStatusStrg>PARTIAL</responseStatusStrg>",
                Paging::Unknown,
            ),
            ("<responseStatusStrg/>", Paging::Unknown),
            ("<responseStatusStrg></responseStatusStrg>", Paging::Unknown),
            ("", Paging::Unknown),
            (
                "<responseStatusStrgX>OK</responseStatusStrgX>",
                Paging::Unknown,
            ),
            (
                "<responseStatusStrg>OK</responseStatusStrg>\
                 <responseStatusStrg>MORE</responseStatusStrg>",
                Paging::Unknown,
            ),
        ] {
            assert_eq!(page(head, 2), paging, "{}", head);
        }
        // a status cut off at the end of the reply
        assert_eq!(
            parse_page("n", "<CMSearchResult><responseStatusStrg>MO")
                .unwrap()
                .paging,
            Paging::Unknown
        );
    }

    #[test]
    fn user_name_that_closes_its_item_early() {
        // firmware that does not escape `<`: the name ends the item, and
        // what follows it lands between the items
        let early = failed_login(
            "a</searchMatchItem><responseStatusStrg>OK</responseStatusStrg>\
             <searchMatchItem><ipAddress>203.0.113.9</ipAddress>",
        );
        let raw = format!(
            "{}{}{}</matchList></CMSearchResult>",
            PAGE_HEAD,
            early,
            page_item("admin")
        );
        let page = parse_page("n", &raw).unwrap();
        // the cut item and the forged one do not parse; the real one after
        // them counts for its own address
        assert_eq!((page.items, page.events.len(), page.skipped), (3, 1, 2));
        assert_eq!(page.events[0].ip, Some("198.51.100.7".parse().unwrap()));
        // the injected OK next to the real MORE: not the last page
        assert_eq!(page.paging, Paging::Unknown);
    }

    #[test]
    fn bare_ampersands_are_text() {
        assert!(matches!(
            escape_bare_amps("a &amp; &lt;&gt;&quot;&apos; &#65; &#x41; &#x1F600;"),
            Cow::Borrowed(_)
        ));
        assert_eq!(
            escape_bare_amps("a & b&c &#1; &#xZZ; &nbsp; &#; &#x; &amp &"),
            "a &amp; b&amp;c &amp;#1; &amp;#xZZ; &amp;nbsp; &amp;#; &amp;#x; &amp;amp &amp;"
        );
        // `&` next to injected markup changes nothing about the markup: the
        // entry counts for its own address, or not at all
        let one = |user: &str| {
            let raw = format!(
                "{}{}</matchList></CMSearchResult>",
                PAGE_HEAD,
                failed_login(user)
            );
            parse_page("n", &raw).unwrap()
        };
        let page = one("a & b<ipAddress>203.0.113.9</ipAddress>&");
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].ip, Some("198.51.100.7".parse().unwrap()));
        assert_eq!(page.events[0].user, "a & b203.0.113.9&");
        let page = one("&</userName><ipAddress>203.0.113.9</ipAddress><userName>&");
        assert_eq!((page.events.len(), page.ambiguous.len()), (0, 1));
        assert_eq!(page.ambiguous[0].ip, None);
        // escaped markup stays text
        let page = one("&lt;ipAddress&gt;203.0.113.9&lt;/ipAddress&gt;");
        assert_eq!(page.events[0].ip, Some("198.51.100.7".parse().unwrap()));
        assert_eq!(page.events[0].user, "<ipAddress>203.0.113.9</ipAddress>");
    }
}
