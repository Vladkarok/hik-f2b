//! RouterOS v7 REST client: adds addresses to a firewall address-list and
//! checks that a firewall rule blocks that list.
//!
//! There is no JSON parser here. Where an answer is needed, the router is
//! asked to filter (`property=value` in the query string) and to return only
//! the properties needed (`.proplist`), so that every value in the reply is
//! an id, an address or `true`/`false`, and the reply is only taken apart
//! into its objects, e.g. `[]` or `[{".id":"*1"},{".id":"*2","disabled":"true"}]`.
//! An answer that does not have the shape asked for (an HTML page from a
//! proxy, say) is an error, never an empty list.

use crate::action::{BanError, BanTime, Firewall, HealthError};
use crate::config::MikrotikCfg;
use crate::{http, util};
use std::net::Ipv4Addr;

const MAX_BODY: u64 = 1024 * 1024;

/// The firewall tables searched for a rule that uses the address-list, in
/// this order. `raw` first: that is where the README puts the drop rule.
const RULE_TABLES: [&str; 2] = ["ip/firewall/raw", "ip/firewall/filter"];
/// The property a rule must match on, with the address-list as its value.
const RULE_LIST_PROPERTY: &str = "src-address-list";
/// The rule properties asked for. A rule counts unless its reply has
/// `"disabled":"true"` or `"invalid":"true"`. RouterOS 7.18.1 leaves
/// `disabled` out of some enabled rules (in `raw` and in `filter`), so a
/// `disabled=false` filter would miss them; it marks a rule `invalid` (and
/// stops using it) when, for example, the interface list it names is
/// removed. Dynamic rules report neither property.
const RULE_PROPERTIES: &str = ".id,disabled,invalid";
/// Part of RouterOS's error text for a duplicate address-list entry. Only a
/// shortcut: without it the router is asked whether the entry exists.
const DUPLICATE_TEXT: &str = "already have";

pub struct Mikrotik {
    base: String,
    pub list: String,
    check_rule: bool,
    agent: ureq::Agent,
    auth: String,
}

/// The rules of one table that use the address-list.
#[derive(Debug, Default, PartialEq)]
struct Rules {
    usable: usize,
    disabled: usize,
    invalid: usize,
}

/// Why rules were left out, for the text of the check: empty, or e.g.
/// `; left out: 1 disabled, 2 invalid`.
fn left_out(disabled: usize, invalid: usize) -> String {
    let parts: Vec<String> = [(disabled, "disabled"), (invalid, "invalid")]
        .iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, what)| format!("{} {}", n, what))
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!("; left out: {}", parts.join(", "))
    }
}

/// The start of an answer, for an error message.
fn shown(body: &str) -> String {
    format!("{:?}", util::sanitize(body.trim(), 40))
}

impl Mikrotik {
    pub fn new(cfg: &MikrotikCfg) -> Result<Mikrotik, String> {
        let credentials = format!("{}:{}", cfg.user, cfg.password);
        Ok(Mikrotik {
            base: format!("{}/rest", cfg.url),
            list: cfg.address_list.clone(),
            check_rule: cfg.check_rule,
            agent: http::agent(&cfg.url, cfg.ca_file.as_deref(), http::DEFAULT_TIMEOUT)
                .map_err(|e| format!("mikrotik: {}", e))?,
            auth: format!("Basic {}", util::b64(credentials.as_bytes())),
        })
    }

    fn failure(code: u16, resp: ureq::Response) -> String {
        let detail = http::read_body(resp, 64 * 1024).unwrap_or_default();
        format!("HTTP {}: {}", code, util::sanitize(&detail, 200))
    }

    /// An error status that says nothing about one address: a refused login
    /// or anything else the router (or something in front of it) answers.
    fn status_error(code: u16, resp: ureq::Response) -> BanError {
        let message = Self::failure(code, resp);
        match code {
            401 | 403 => BanError::Login(message),
            _ => BanError::Router(message),
        }
    }

    /// `GET /rest/<path>?<filters>&.proplist=<properties>` and the reply
    /// body. The query values are percent-encoded by the HTTP client.
    fn get(
        &self,
        path: &str,
        filters: &[(&str, &str)],
        properties: &str,
    ) -> Result<String, BanError> {
        let mut req = self.agent.get(&format!("{}/{}", self.base, path));
        for (key, value) in filters {
            req = req.query(key, value);
        }
        let result = req
            .query(".proplist", properties)
            .set("Authorization", &self.auth)
            .call();
        match result {
            Ok(resp) if resp.status() == 200 => {
                http::read_body(resp, MAX_BODY).map_err(BanError::Transport)
            }
            Ok(resp) => Err(BanError::Router(format!(
                "unexpected HTTP {}",
                resp.status()
            ))),
            Err(ureq::Error::Status(code, resp)) => Err(Self::status_error(code, resp)),
            Err(e) => Err(BanError::Transport(util::sanitize(&e.to_string(), 200))),
        }
    }

    /// `get` for a list of objects that each have `required`.
    fn get_list(
        &self,
        path: &str,
        filters: &[(&str, &str)],
        properties: &str,
        required: &str,
    ) -> Result<Vec<String>, BanError> {
        let body = self.get(path, filters, properties)?;
        objects(&body)
            .filter(|objects| {
                objects
                    .iter()
                    .all(|object| members(object, required, None) == 1)
            })
            .map(|objects| objects.into_iter().map(str::to_string).collect())
            .ok_or_else(|| {
                BanError::Router(format!(
                    "the answer to /{} is not the list asked for: {}",
                    path,
                    shown(&body)
                ))
            })
    }

    /// Number of entries currently in the address-list (shown at startup;
    /// deliberately not part of the `Firewall` interface).
    pub fn count(&self) -> Result<usize, String> {
        self.get_list(
            "ip/firewall/address-list",
            &[("list", self.list.as_str())],
            "address",
            "address",
        )
        .map(|entries| entries.len())
        .map_err(|e| e.to_string())
    }

    /// Whether the address-list has an entry for `ip`.
    fn listed(&self, ip: Ipv4Addr) -> Result<bool, BanError> {
        let address = ip.to_string();
        self.get_list(
            "ip/firewall/address-list",
            &[("list", self.list.as_str()), ("address", address.as_str())],
            ".id",
            ".id",
        )
        .map(|entries| !entries.is_empty())
    }

    /// The rules in `table` that use the address-list.
    fn rules(&self, table: &str) -> Result<Rules, BanError> {
        let rules = self.get_list(
            table,
            &[(RULE_LIST_PROPERTY, self.list.as_str())],
            RULE_PROPERTIES,
            ".id",
        )?;
        let mut out = Rules::default();
        for rule in &rules {
            if members(rule, "disabled", Some("true")) > 0 {
                out.disabled += 1;
            } else if members(rule, "invalid", Some("true")) > 0 {
                out.invalid += 1;
            } else {
                out.usable += 1;
            }
        }
        Ok(out)
    }
}

/// The objects of a JSON array whose values hold no `{`, `}`, `[` or `]`
/// (true of every reply limited by `.proplist` to ids, addresses and flags),
/// each with its braces; `None` when the text is not such an array.
fn objects(body: &str) -> Option<Vec<&str>> {
    let inner = body.trim().strip_prefix('[')?.strip_suffix(']')?;
    let mut out = Vec::new();
    let mut rest = inner.trim_start();
    while !rest.is_empty() {
        if !out.is_empty() {
            rest = rest.strip_prefix(',')?.trim_start();
        }
        if !rest.starts_with('{') {
            return None;
        }
        let end = rest.find('}')?;
        let object = &rest[..=end];
        if object[1..].contains(['{', '[', ']']) {
            return None;
        }
        out.push(object);
        rest = rest[end + 1..].trim_start();
    }
    Some(out)
}

/// A single JSON object, as RouterOS answers a successful `PUT` with the
/// entry it made.
fn is_object(body: &str) -> bool {
    let body = body.trim();
    body.starts_with('{') && body.ends_with('}')
}

/// How many members named `name` (with the string value `value`, if given)
/// a JSON reply has, allowing whitespace around the colon. Only safe on
/// replies limited by `.proplist`, where no other string can hold the
/// pattern; a quote inside a value would be escaped anyway.
fn members(body: &str, name: &str, value: Option<&str>) -> usize {
    let key = format!("\"{}\"", name);
    body.match_indices(&key)
        .filter(|(at, _)| {
            let rest = body[at + key.len()..].trim_start();
            let Some(rest) = rest.strip_prefix(':') else {
                return false;
            };
            match value {
                None => true,
                Some(v) => rest.trim_start().starts_with(&format!("\"{}\"", v)),
            }
        })
        .count()
}

impl Firewall for Mikrotik {
    /// Adds `ip` to the address-list. Returns `false` when the router
    /// already lists the address (with or without a timeout).
    fn ban(&self, ip: Ipv4Addr, bantime: BanTime, comment: &str) -> Result<bool, BanError> {
        // An entry without a timeout is static: RouterOS saves it in its
        // configuration, while timed entries live in memory only.
        let timeout = match bantime {
            BanTime::Seconds(s) => format!(",\"timeout\":\"{}\"", util::fmt_timeout(s)),
            BanTime::Permanent => String::new(),
        };
        let body = format!(
            "{{\"list\":\"{}\",\"address\":\"{}\"{},\"comment\":\"{}\"}}",
            util::json_escape(&self.list),
            ip,
            timeout,
            util::json_escape(comment)
        );
        let result = self
            .agent
            .put(&format!("{}/ip/firewall/address-list", self.base))
            .set("Authorization", &self.auth)
            .set("Content-Type", "application/json")
            .send_string(&body);
        match result {
            Ok(resp) if (200..300).contains(&resp.status()) => {
                let answer = http::read_body(resp, MAX_BODY).map_err(BanError::Transport)?;
                if is_object(&answer) {
                    Ok(true)
                } else {
                    // Something other than RouterOS answered: whether the
                    // entry was made is not known. The next attempt finds
                    // out (an existing entry is "already listed").
                    Err(BanError::Router(format!(
                        "the answer to the ban is not the JSON object RouterOS sends: {}",
                        shown(&answer)
                    )))
                }
            }
            Ok(resp) => Err(BanError::Router(format!(
                "unexpected HTTP {}",
                resp.status()
            ))),
            Err(ureq::Error::Status(code, resp))
                if (400..500).contains(&code) && code != 401 && code != 403 =>
            {
                // An answer about this request.
                let message = Self::failure(code, resp);
                if message.contains(DUPLICATE_TEXT) {
                    return Ok(false);
                }
                // The wording of the duplicate error is not an interface;
                // whether the entry exists is. A lookup that fails says the
                // router cannot be used at all.
                match self.listed(ip) {
                    Ok(true) => Ok(false),
                    Ok(false) => Err(BanError::Refused(message)),
                    Err(e) => Err(e),
                }
            }
            Err(ureq::Error::Status(code, resp)) => Err(Self::status_error(code, resp)),
            Err(e) => Err(BanError::Transport(util::sanitize(&e.to_string(), 200))),
        }
    }

    /// Reachable with our credentials and, unless `check_rule` is off, at
    /// least one rule in `raw` or `filter` that is neither disabled nor
    /// invalid has the address-list as its `src-address-list`. The rule's
    /// action and chain are not looked at.
    fn check(&self) -> Result<String, HealthError> {
        let unusable = |e: BanError| HealthError::Unusable(e.to_string());
        if !self.check_rule {
            let body = self.get("system/identity", &[], "name").map_err(unusable)?;
            if !is_object(&body) || members(&body, "name", None) != 1 {
                return Err(unusable(BanError::Router(format!(
                    "the answer to /system/identity is not the JSON asked for: {}",
                    shown(&body)
                ))));
            }
            return Ok("router answers (rule check is off)".to_string());
        }
        let (mut disabled, mut invalid) = (0, 0);
        for table in RULE_TABLES {
            let rules = self.rules(table).map_err(unusable)?;
            disabled += rules.disabled;
            invalid += rules.invalid;
            if rules.usable > 0 {
                return Ok(format!(
                    "{} enabled rule(s) in /{} with {}={}{}",
                    rules.usable,
                    table,
                    RULE_LIST_PROPERTY,
                    self.list,
                    left_out(disabled, invalid)
                ));
            }
        }
        Err(HealthError::NotEnforced(format!(
            "no enabled rule in /{} or /{} has {}={}{}",
            RULE_TABLES[0],
            RULE_TABLES[1],
            RULE_LIST_PROPERTY,
            self.list,
            left_out(disabled, invalid)
        )))
    }

    fn describe(&self) -> String {
        format!("MikroTik address-list {}", self.list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_rules_from_real_replies() {
        // RouterOS 7.18.1: an enabled raw rule has no `disabled` member
        let raw = r#"[{".id":"*3"}]"#;
        assert_eq!(members(raw, ".id", None), 1);
        assert_eq!(members(raw, "disabled", Some("true")), 0);
        let filter = r#"[{".id":"*17","disabled":"false"},{".id":"*1B","disabled":"true"},{".id":"*15","disabled":"false"}]"#;
        assert_eq!(members(filter, ".id", None), 3);
        assert_eq!(members(filter, "disabled", Some("true")), 1);
        let spaced = "[ { \".id\" : \"*1\", \"disabled\" :\t\"true\" } ]";
        assert_eq!(members(spaced, ".id", None), 1);
        assert_eq!(members(spaced, "disabled", Some("true")), 1);
        assert_eq!(members("[]", ".id", None), 0);
        // a value that only looks like a member name is not one
        assert_eq!(members(r#"[{"comment":".id"}]"#, ".id", None), 0);
    }

    #[test]
    fn splits_replies_into_objects() {
        // as RouterOS 7.18.1 answers `.proplist=.id,disabled,invalid`:
        // `disabled` is there on some enabled rules and not on others, a
        // dynamic rule has neither property
        let reply = r#"[{".id":"*3","invalid":"false"},{".id":"*4","disabled":"false","invalid":"false"},{".id":"*5","disabled":"true","invalid":"false"},{".id":"*6","invalid":"true"},{".id":"*7"}]"#;
        let objects = objects(reply).unwrap();
        assert_eq!(objects.len(), 5);
        assert_eq!(objects[3], r#"{".id":"*6","invalid":"true"}"#);
        assert_eq!(super::objects("[]"), Some(vec![]));
        assert_eq!(super::objects(" [ ] "), Some(vec![]));
        assert_eq!(
            super::objects("[ {\"a\":\"1\"} , {\"a\":\"2\"} ]")
                .unwrap()
                .len(),
            2
        );
        // anything else is not a reply
        for bad in [
            "",
            "<html><body>proxy error</body></html>",
            "{\".id\":\"*1\"}",
            "[{\".id\":\"*1\"}",
            "[{\".id\":\"*1\"} {\".id\":\"*2\"}]",
            "[{\".id\":\"*1\"},]",
            "[\"*1\"]",
            "[{\".id\":{\"x\":1}}]",
            "[{\".id\":[1]}]",
        ] {
            assert_eq!(super::objects(bad), None, "{:?}", bad);
        }
        assert!(is_object("{\".id\":\"*1\",\"list\":\"x\"}\n"));
        assert!(!is_object("<html></html>"));
        assert!(!is_object("[]"));
    }

    #[test]
    fn names_the_rules_left_out() {
        assert_eq!(left_out(0, 0), "");
        assert_eq!(left_out(1, 0), "; left out: 1 disabled");
        assert_eq!(left_out(0, 2), "; left out: 2 invalid");
        assert_eq!(left_out(1, 2), "; left out: 1 disabled, 2 invalid");
    }
}
