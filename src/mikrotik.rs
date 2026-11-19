//! RouterOS v7 REST client: adds addresses to a firewall address-list.

use crate::action::{BanError, BanTime, Firewall};
use crate::config::MikrotikCfg;
use crate::{http, util};
use std::net::Ipv4Addr;

const MAX_BODY: u64 = 1024 * 1024;

pub struct Mikrotik {
    base: String,
    pub list: String,
    agent: ureq::Agent,
    auth: String,
}

impl Mikrotik {
    pub fn new(cfg: &MikrotikCfg) -> Result<Mikrotik, String> {
        let credentials = format!("{}:{}", cfg.user, cfg.password);
        Ok(Mikrotik {
            base: format!("{}/rest", cfg.url),
            list: cfg.address_list.clone(),
            agent: http::agent(&cfg.url, cfg.ca_file.as_deref(), http::DEFAULT_TIMEOUT)
                .map_err(|e| format!("mikrotik: {}", e))?,
            auth: format!("Basic {}", util::b64(credentials.as_bytes())),
        })
    }

    fn failure(code: u16, resp: ureq::Response) -> String {
        let detail = http::read_body(resp, 64 * 1024).unwrap_or_default();
        format!("HTTP {}: {}", code, util::sanitize(&detail, 200))
    }

    /// Number of entries currently in the address-list (startup self-check;
    /// deliberately not part of the `Firewall` interface).
    pub fn count(&self) -> Result<usize, String> {
        let result = self
            .agent
            .get(&format!("{}/ip/firewall/address-list", self.base))
            .query("list", &self.list)
            .query(".proplist", "address")
            .set("Authorization", &self.auth)
            .call();
        match result {
            Ok(resp) if resp.status() == 200 => Ok(http::read_body(resp, MAX_BODY)?
                .matches("\"address\"")
                .count()),
            Ok(resp) => Err(format!("unexpected HTTP {}", resp.status())),
            Err(ureq::Error::Status(code, resp)) => Err(Self::failure(code, resp)),
            Err(e) => Err(util::sanitize(&e.to_string(), 200)),
        }
    }
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
                if message.contains("already have") {
                    Ok(false)
                } else {
                    Err(BanError::Refused(message))
                }
            }
            Err(e) => Err(BanError::Transport(util::sanitize(&e.to_string(), 200))),
        }
    }

    fn describe(&self) -> String {
        format!("MikroTik address-list {}", self.list)
    }
}
