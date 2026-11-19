//! What the engine does with an address that reached the threshold: an
//! optional firewall that bans it and an optional notifier that reports it.
//! The engine only knows these two interfaces, so another firewall or
//! messenger can be added without touching the decision logic.

use crate::util;
use std::net::Ipv4Addr;

/// How long a ban lasts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BanTime {
    /// The firewall lifts the ban itself after this many seconds.
    Seconds(u64),
    /// The ban stays until it is removed by hand. On RouterOS it is a static
    /// entry, which is saved in the configuration and survives a reboot.
    Permanent,
}

impl BanTime {
    /// The value of the `{bantime}` placeholder: `1d00:00:00` or `permanent`.
    pub fn label(&self) -> String {
        match self {
            BanTime::Seconds(s) => util::fmt_timeout(*s),
            BanTime::Permanent => "permanent".to_string(),
        }
    }

    /// The words after "banned": `for 1d00:00:00` or `permanently`.
    pub fn phrase(&self) -> String {
        match self {
            BanTime::Seconds(s) => format!("for {}", util::fmt_timeout(*s)),
            BanTime::Permanent => "permanently".to_string(),
        }
    }
}

impl std::fmt::Display for BanTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BanTime::Seconds(s) => write!(f, "{}s", s),
            BanTime::Permanent => write!(f, "permanent"),
        }
    }
}

/// Why a ban was not applied. The difference matters to the caller: a
/// transport failure means the firewall is unreachable (or hangs), so trying
/// further addresses in the same cycle would only stall polling; a refusal
/// concerns this one request.
#[derive(Debug, Clone, PartialEq)]
pub enum BanError {
    Transport(String),
    Refused(String),
}

impl std::fmt::Display for BanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BanError::Transport(m) => write!(f, "cannot reach the firewall: {}", m),
            BanError::Refused(m) => write!(f, "refused: {}", m),
        }
    }
}

/// Why the firewall cannot be relied on.
#[derive(Debug, Clone, PartialEq)]
pub enum HealthError {
    /// It cannot be reached, refuses our login or answers with an error.
    Unusable(String),
    /// It answers, but nothing blocks the addresses it lists.
    NotEnforced(String),
}

impl std::fmt::Display for HealthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthError::Unusable(m) | HealthError::NotEnforced(m) => f.write_str(m),
        }
    }
}

pub trait Firewall {
    /// Blocks `ip` for `bantime`. Returns `Ok(false)` when the firewall
    /// already lists the address; an existing entry is left as it is.
    fn ban(&self, ip: Ipv4Addr, bantime: BanTime, comment: &str) -> Result<bool, BanError>;
    /// Checks that bans can be applied and that listed addresses are
    /// actually blocked. `Ok` carries a short description of what was found.
    /// Must change nothing on the firewall.
    fn check(&self) -> Result<String, HealthError>;
    /// A short human-readable name for log lines, e.g. the address-list.
    fn describe(&self) -> String;
}

pub trait Notifier {
    /// Sends one message. Errors must not contain secrets.
    fn send(&self, text: &str) -> Result<(), String>;
}

/// The values a notification template can refer to.
pub struct BanInfo<'a> {
    pub ip: Ipv4Addr,
    /// Empty, or ` (<flag> <code>)` when the country is known.
    pub country: &'a str,
    /// What was done, e.g. `banned for 1d00:00:00`.
    pub action: &'a str,
    pub bantime: &'a str,
    pub nvr: &'a str,
    /// Already sanitised, but still attacker-chosen text.
    pub user: &'a str,
    pub count: usize,
    pub findtime: i64,
}

/// Fills a notification template. `{user}` is replaced last, so placeholders
/// that an attacker types as a user name are never expanded.
pub fn render(template: &str, ban: &BanInfo) -> String {
    template
        .replace("{ip}", &ban.ip.to_string())
        .replace("{country}", ban.country)
        .replace("{action}", ban.action)
        .replace("{bantime}", ban.bantime)
        .replace("{nvr}", ban.nvr)
        .replace("{count}", &ban.count.to_string())
        .replace("{findtime}", &ban.findtime.to_string())
        .replace("{user}", ban.user)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_placeholders() {
        let info = BanInfo {
            ip: "198.51.100.7".parse().unwrap(),
            country: " (\u{1f1f2}\u{1f1e9} MD)",
            action: "banned for 1d00:00:00",
            bantime: "1d00:00:00",
            nvr: "nvr1",
            user: "{ip}{action}{country}",
            count: 5,
            findtime: 3600,
        };
        assert_eq!(
            render(
                "{ip} {action}|{bantime}|{nvr}|{user}|{count}|{findtime}",
                &info
            ),
            "198.51.100.7 banned for 1d00:00:00|1d00:00:00|nvr1|{ip}{action}{country}|5|3600"
        );
        assert_eq!(
            render("{ip}{country} {action}", &info),
            "198.51.100.7 (\u{1f1f2}\u{1f1e9} MD) banned for 1d00:00:00"
        );
        let unknown = BanInfo {
            country: "",
            ..info
        };
        assert_eq!(
            render("{ip}{country} {action}", &unknown),
            "198.51.100.7 banned for 1d00:00:00"
        );
    }

    #[test]
    fn ban_time_wording() {
        let day = BanTime::Seconds(86400);
        assert_eq!(day.label(), "1d00:00:00");
        assert_eq!(day.phrase(), "for 1d00:00:00");
        assert_eq!(day.to_string(), "86400s");
        assert_eq!(BanTime::Permanent.label(), "permanent");
        assert_eq!(BanTime::Permanent.phrase(), "permanently");
        assert_eq!(BanTime::Permanent.to_string(), "permanent");
    }
}
