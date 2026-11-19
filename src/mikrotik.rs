//! RouterOS v7 REST client: adds addresses to a firewall address-list and
//! checks that a firewall rule blocks that list.
//!
//! There is no JSON parser here. Where an answer is needed, the router is
//! asked to filter (`property=value` in the query string) and to return only
//! the properties needed (`.proplist`), and the members of the reply are only
//! counted, e.g. `[]` or `[{".id":"*1"},{".id":"*2","disabled":"true"}]`.

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
/// The rule properties asked for. A rule is enabled unless its reply has
/// `"disabled":"true"`: RouterOS 7.18 leaves `disabled` out of enabled
/// `raw` rules altogether, so a `disabled=false` filter would miss them.
const RULE_PROPERTIES: &str = ".id,disabled";
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
            Ok(resp) => Err(BanError::Refused(format!(
                "unexpected HTTP {}",
                resp.status()
            ))),
            Err(ureq::Error::Status(code, resp)) => {
                Err(BanError::Refused(Self::failure(code, resp)))
            }
            Err(e) => Err(BanError::Transport(util::sanitize(&e.to_string(), 200))),
        }
    }

    /// Number of entries currently in the address-list (shown at startup;
    /// deliberately not part of the `Firewall` interface).
    pub fn count(&self) -> Result<usize, String> {
        self.get(
            "ip/firewall/address-list",
            &[("list", self.list.as_str())],
            "address",
        )
        .map(|body| members(&body, "address", None))
        .map_err(|e| e.to_string())
    }

    /// Whether the address-list has an entry for `ip`.
    fn listed(&self, ip: Ipv4Addr) -> Result<bool, BanError> {
        let address = ip.to_string();
        self.get(
            "ip/firewall/address-list",
            &[("list", self.list.as_str()), ("address", address.as_str())],
            ".id",
        )
        .map(|body| members(&body, ".id", None) > 0)
    }

    /// Enabled rules in `table` that use the address-list.
    fn enabled_rules(&self, table: &str) -> Result<usize, BanError> {
        let body = self.get(
            table,
            &[(RULE_LIST_PROPERTY, self.list.as_str())],
            RULE_PROPERTIES,
        )?;
        let rules = members(&body, ".id", None);
        let disabled = members(&body, "disabled", Some("true"));
        Ok(rules.saturating_sub(disabled))
    }
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
            Ok(resp) if (200..300).contains(&resp.status()) => Ok(true),
            Ok(resp) => Err(BanError::Refused(format!(
                "unexpected HTTP {}",
                resp.status()
            ))),
            Err(ureq::Error::Status(code, resp)) => {
                let message = Self::failure(code, resp);
                if message.contains(DUPLICATE_TEXT) {
                    return Ok(false);
                }
                // The wording of the duplicate error is not an interface;
                // whether the entry exists is. A refused login would refuse
                // the lookup too.
                if code == 401 || code == 403 {
                    return Err(BanError::Refused(message));
                }
                match self.listed(ip) {
                    Ok(true) => Ok(false),
                    Ok(false) | Err(BanError::Refused(_)) => Err(BanError::Refused(message)),
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(BanError::Transport(util::sanitize(&e.to_string(), 200))),
        }
    }

    /// Reachable with our credentials and, unless `check_rule` is off, at
    /// least one enabled rule in `raw` or `filter` has the address-list as
    /// its `src-address-list` (a rule without a `disabled` member counts as
    /// enabled). The rule's action and chain are not looked at.
    fn check(&self) -> Result<String, HealthError> {
        let unusable = |e: BanError| HealthError::Unusable(e.to_string());
        if !self.check_rule {
            self.get("system/identity", &[], "name").map_err(unusable)?;
            return Ok("router answers (rule check is off)".to_string());
        }
        for table in RULE_TABLES {
            let n = self.enabled_rules(table).map_err(unusable)?;
            if n > 0 {
                return Ok(format!(
                    "{} enabled rule(s) in /{} with {}={}",
                    n, table, RULE_LIST_PROPERTY, self.list
                ));
            }
        }
        Err(HealthError::NotEnforced(format!(
            "no enabled rule in /{} or /{} has {}={}",
            RULE_TABLES[0], RULE_TABLES[1], RULE_LIST_PROPERTY, self.list
        )))
    }

    fn describe(&self) -> String {
        format!("MikroTik address-list {}", self.list)
    }
}

#[cfg(test)]
mod tests {
    use super::members;

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
}
