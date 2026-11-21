//! Configuration: a small INI file, validated strictly.

use crate::action::BanTime;
use crate::util::is_name;
use regex_lite::Regex;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

pub type Section = BTreeMap<String, String>;

pub const DEFAULT_IGNORE: &str = "127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16";
/// Seen on real firmware as `.../Exception/illlegealAccess` (sic).
pub const DEFAULT_FILTER: &str = r"ill\w*(access|login)";
/// `{action}` says what happened: banned, would be banned (dry run), or only
/// detected (no firewall configured).
/// `{country}` is empty unless `country_db` gave a code, so the default text
/// is unchanged without one.
pub const DEFAULT_MESSAGE: &str =
    "\u{26d4} hik-f2b: {ip}{country} {action}\\nNVR: {nvr}\\nUser tried: {user}\\nFailed logins: {count} within {findtime} s";
/// `ca_file = public` trusts the bundled public CA roots instead of a file.
pub const PUBLIC_ROOTS: &str = "public";

// Structs holding secrets deliberately do not derive Debug.
#[derive(Clone)]
pub struct MikrotikCfg {
    pub url: String,
    pub user: String,
    pub password: String,
    pub address_list: String,
    /// `None` = the bundled public roots (`ca_file = public`).
    pub ca_file: Option<PathBuf>,
    /// Whether the health check looks for a rule that uses the list.
    pub check_rule: bool,
}

#[derive(Clone)]
pub struct NvrCfg {
    pub name: String,
    pub url: String,
    pub user: String,
    pub password: String,
    pub ca_file: Option<PathBuf>,
}

#[derive(Clone)]
pub struct TelegramCfg {
    pub api_url: String,
    pub token: String,
    pub chat_id: String,
    pub thread_id: Option<u64>,
    pub silent: bool,
    pub message: String,
    /// Whether health alerts go to the chat (they are always logged).
    pub health_alerts: bool,
}

pub struct Config {
    pub poll_interval: u64,
    pub maxretry: usize,
    pub findtime: i64,
    pub bantime: BanTime,
    pub lookback: i64,
    pub auth_backoff: u64,
    /// How long a problem must last before it is alerted.
    pub alert_after: u64,
    pub max_bans_per_hour: usize,
    pub state_file: PathBuf,
    pub ignore: Vec<Net>,
    pub meta_id: String,
    pub log_filter: Regex,
    pub dry_run: bool,
    /// An offline MaxMind DB file for the country of banned addresses
    /// (display only). `None` = off.
    pub country_db: Option<PathBuf>,
    /// True when a password or token is written in the config itself
    /// rather than read from a separate secret file.
    pub inline_secrets: bool,
    /// `None` = notify-only mode: nothing is banned.
    pub mikrotik: Option<MikrotikCfg>,
    pub nvrs: Vec<NvrCfg>,
    pub telegram: Option<TelegramCfg>,
}

/// An IPv4 network such as `10.0.0.0/8`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Net {
    addr: u32,
    mask: u32,
}

impl Net {
    pub fn parse(text: &str) -> Result<Net, String> {
        let (addr, len) = match text.split_once('/') {
            Some((a, l)) => (
                a,
                l.parse::<u32>()
                    .map_err(|_| format!("bad prefix in {}", text))?,
            ),
            None => (text, 32),
        };
        if len > 32 {
            return Err(format!("bad prefix in {}", text));
        }
        let addr: Ipv4Addr = addr
            .parse()
            .map_err(|_| format!("{} is not an IPv4 address or network", text))?;
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        Ok(Net {
            addr: u32::from(addr) & mask,
            mask,
        })
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask == self.addr
    }
}

pub fn parse_ini(text: &str) -> Result<BTreeMap<String, Section>, String> {
    let mut out: BTreeMap<String, Section> = BTreeMap::new();
    let mut current: Option<String> = None;
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let name = rest
                .strip_suffix(']')
                .ok_or_else(|| format!("line {}: bad section header", n + 1))?
                .trim()
                .to_ascii_lowercase();
            if out.contains_key(&name) {
                return Err(format!("line {}: section [{}] appears twice", n + 1, name));
            }
            out.insert(name.clone(), Section::new());
            current = Some(name);
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected key = value", n + 1))?;
        let section = current
            .as_ref()
            .and_then(|name| out.get_mut(name))
            .ok_or_else(|| format!("line {}: key outside of a section", n + 1))?;
        section.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    Ok(out)
}

fn number(sec: &Section, key: &str, default: u64, min: u64, max: u64) -> Result<u64, String> {
    let value = match sec.get(key) {
        Some(v) => v
            .parse::<u64>()
            .map_err(|_| format!("{} must be a whole number", key))?,
        None => default,
    };
    if value < min || value > max {
        return Err(format!("{} must be between {} and {}", key, min, max));
    }
    Ok(value)
}

/// A whole number of seconds, or a whole number with one unit suffix:
/// `90`, `90s`, `10m`, `12h`, `7d`, `2w`. `None` when the text is neither.
/// Values too large for a u64 come out as `u64::MAX`, so that they fail the
/// bounds check rather than the syntax check.
fn parse_seconds(text: &str) -> Option<u64> {
    let (digits, factor) = match text.as_bytes().last()? {
        b's' => (&text[..text.len() - 1], 1),
        b'm' => (&text[..text.len() - 1], 60),
        b'h' => (&text[..text.len() - 1], 3600),
        b'd' => (&text[..text.len() - 1], 86400),
        b'w' => (&text[..text.len() - 1], 7 * 86400),
        _ => (text, 1),
    };
    // `str::parse` alone would also accept a leading `+`.
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value = digits.parse::<u64>().unwrap_or(u64::MAX);
    Some(value.saturating_mul(factor))
}

/// A time setting in seconds; see `parse_seconds` for the syntax.
fn duration(sec: &Section, key: &str, default: u64, min: u64, max: u64) -> Result<u64, String> {
    let value = match sec.get(key) {
        Some(v) => parse_seconds(v).ok_or_else(|| {
            format!(
                "{} must be a whole number of seconds, optionally with one of the suffixes \
                 s, m, h, d, w (e.g. 90, 10m, 12h, 7d)",
                key
            )
        })?,
        None => default,
    };
    if value < min || value > max {
        return Err(format!(
            "{} must be between {} and {} seconds",
            key, min, max
        ));
    }
    Ok(value)
}

/// The longest timeout RouterOS accepts for an address-list entry,
/// `35w3d13h13m56s`; a longer one fails with "value of timeout is out of
/// range". It is also the limit in notify-only mode, so that a config works
/// the same with and without a router.
pub const MAX_BANTIME: u64 = 21_474_836;

/// `bantime`: a time setting, or `permanent`.
fn bantime(sec: &Section) -> Result<BanTime, String> {
    match sec.get("bantime") {
        Some(v) if v.eq_ignore_ascii_case("permanent") => Ok(BanTime::Permanent),
        Some(v) if parse_seconds(v).is_some_and(|s| s > MAX_BANTIME) => Err(format!(
            "bantime must be at most {} seconds (35w3d13h13m56s, about 248 days): RouterOS \
             accepts no longer timeout; for a longer ban use bantime = permanent",
            MAX_BANTIME
        )),
        _ => duration(sec, "bantime", 86400, 60, MAX_BANTIME)
            .map(BanTime::Seconds)
            .map_err(|e| format!("{} (or the word permanent)", e)),
    }
}

fn boolean(sec: &Section, key: &str, default: bool) -> Result<bool, String> {
    match sec.get(key).map(|v| v.to_ascii_lowercase()) {
        None => Ok(default),
        Some(v) if ["1", "true", "yes", "on"].contains(&v.as_str()) => Ok(true),
        Some(v) if ["0", "false", "no", "off"].contains(&v.as_str()) => Ok(false),
        Some(_) => Err(format!("{} must be true or false", key)),
    }
}

/// A secret comes from `<key>_file` (preferred: a mounted secret) or from
/// `<key>` in the config itself.
fn secret(sec: &Section, key: &str, what: &str) -> Result<String, String> {
    let file_key = format!("{}_file", key);
    let value = if let Some(path) = sec.get(&file_key) {
        std::fs::read_to_string(path)
            .map_err(|e| format!("{}: cannot read {}: {}", what, path, e.kind()))?
            .trim_end_matches(['\r', '\n'])
            .to_string()
    } else if let Some(v) = sec.get(key) {
        v.clone()
    } else {
        return Err(format!("{}: {} or {} is required", what, key, file_key));
    };
    if value.is_empty() || value.len() > 256 || value.chars().any(|c| c.is_control()) {
        return Err(format!(
            "{}: {} is empty, too long or has control characters",
            what, key
        ));
    }
    Ok(value)
}

fn required<'a>(sec: &'a Section, key: &str, what: &str) -> Result<&'a str, String> {
    sec.get(key)
        .map(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{}: {} is required", what, key))
}

fn check_user(user: &str, what: &str) -> Result<String, String> {
    let ok = !user.is_empty()
        && user.len() <= 64
        && user
            .chars()
            .all(|c| ('!'..='~').contains(&c) && c != '"' && c != '\\' && c != ':');
    if ok {
        Ok(user.to_string())
    } else {
        Err(format!("{}: user has unsupported characters", what))
    }
}

/// Accepts `http(s)://host[:port]` and nothing else. Endpoints that receive
/// a password or token must be https unless they are on this machine.
pub fn check_url(url: &str, secret_bearing: bool, what: &str) -> Result<String, String> {
    let url = url.trim_end_matches('/');
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(format!("{}: url must start with http:// or https://", what));
    };
    let ok = !rest.is_empty()
        && rest.len() <= 255
        && rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-:[]".contains(c));
    if !ok {
        return Err(format!("{}: url must be just scheme://host[:port]", what));
    }
    let host = if let Some(v6) = rest.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        rest.split(':').next().unwrap_or("")
    };
    let local = host == "localhost" || host == "127.0.0.1" || host == "::1";
    if secret_bearing && !https && !local {
        return Err(format!(
            "{}: url must be https (credentials are sent to it)",
            what
        ));
    }
    Ok(url.to_string())
}

/// `None` means the bundled public roots: either the key is absent or it
/// says `public`.
fn ca_file(sec: &Section) -> Option<PathBuf> {
    sec.get("ca_file")
        .filter(|s| !s.is_empty() && s.as_str() != PUBLIC_ROOTS)
        .map(PathBuf::from)
}

fn mikrotik(m: &Section) -> Result<MikrotikCfg, String> {
    let address_list = m
        .get("address_list")
        .cloned()
        .unwrap_or_else(|| "cctv_ban".to_string());
    if !is_name(&address_list, 64) {
        return Err("mikrotik: address_list may contain only letters, digits, _ - .".to_string());
    }
    let url = check_url(required(m, "url", "mikrotik")?, true, "mikrotik")?;
    // The router holds the ban list, so whoever can impersonate it can make
    // bans silently fail. Trusting every public CA must be a visible choice.
    if url.starts_with("https://") && !m.get("ca_file").is_some_and(|s| !s.is_empty()) {
        return Err(format!(
            "mikrotik: ca_file is required for an https url: the path of the router's CA \
             certificate, or '{}' to trust the bundled public CA roots",
            PUBLIC_ROOTS
        ));
    }
    Ok(MikrotikCfg {
        url,
        user: check_user(required(m, "user", "mikrotik")?, "mikrotik")?,
        password: secret(m, "password", "mikrotik")?,
        address_list,
        ca_file: ca_file(m),
        check_rule: boolean(m, "check_rule", true)?,
    })
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read config {}: {}", path.display(), e.kind()))?;
        Config::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        let ini = parse_ini(text)?;
        let empty = Section::new();
        let g = ini.get("general").unwrap_or(&empty);

        let mut ignore = Vec::new();
        let list = g
            .get("ignoreip")
            .map(|s| s.as_str())
            .unwrap_or(DEFAULT_IGNORE);
        for item in list.split(|c: char| c == ',' || c.is_whitespace()) {
            if !item.is_empty() {
                ignore.push(Net::parse(item).map_err(|e| format!("ignoreip: {}", e))?);
            }
        }

        let meta_id = g
            .get("meta_id")
            .cloned()
            .unwrap_or_else(|| "log.std-cgi.com/Exception".to_string());
        if meta_id.is_empty()
            || meta_id.len() > 128
            || !meta_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "./_-".contains(c))
        {
            return Err("meta_id has unsupported characters".to_string());
        }

        let pattern = g
            .get("log_filter")
            .map(|s| s.as_str())
            .unwrap_or(DEFAULT_FILTER);
        if pattern.len() > 200 {
            return Err("log_filter is too long".to_string());
        }
        let log_filter = Regex::new(&format!("(?i){}", pattern))
            .map_err(|e| format!("log_filter is not a valid regular expression: {}", e))?;

        let mikrotik = match ini.get("mikrotik") {
            Some(m) => Some(mikrotik(m)?),
            None => None,
        };

        let mut nvrs = Vec::new();
        for (name, sec) in &ini {
            let Some(nvr_name) = name.strip_prefix("nvr:") else {
                continue;
            };
            let nvr_name = nvr_name.trim();
            let what = format!("nvr {}", nvr_name);
            if !is_name(nvr_name, 32) {
                return Err(format!(
                    "{}: name may contain only letters, digits, _ - .",
                    what
                ));
            }
            nvrs.push(NvrCfg {
                name: nvr_name.to_string(),
                url: check_url(required(sec, "url", &what)?, false, &what)?,
                user: check_user(required(sec, "user", &what)?, &what)?,
                password: secret(sec, "password", &what)?,
                ca_file: ca_file(sec),
            });
        }
        if nvrs.is_empty() {
            return Err("at least one [nvr:<name>] section is required".to_string());
        }

        let telegram = match ini.get("telegram") {
            Some(t) if boolean(t, "enabled", true)? => Some(Self::telegram(t)?),
            _ => None,
        };

        for name in ini.keys() {
            let known = ["general", "mikrotik", "telegram"].contains(&name.as_str());
            if !known && !name.starts_with("nvr:") {
                return Err(format!("unknown section [{}]", name));
            }
        }

        Ok(Config {
            poll_interval: duration(g, "poll_interval", 30, 5, 3600)?,
            maxretry: number(g, "maxretry", 5, 1, 1000)? as usize,
            findtime: duration(g, "findtime", 3600, 10, 30 * 86400)? as i64,
            bantime: bantime(g)?,
            // The overlap absorbs entries the NVR writes a little late and
            // small clock corrections; 0 would lose them.
            lookback: duration(g, "lookback", 120, 10, 2 * 86400)? as i64,
            auth_backoff: duration(g, "auth_backoff", 900, 60, 86400)?,
            alert_after: duration(g, "alert_after", 600, 60, 7 * 86400)?,
            max_bans_per_hour: number(g, "max_bans_per_hour", 20, 1, 10000)? as usize,
            state_file: PathBuf::from(
                g.get("state_file")
                    .map(|s| s.as_str())
                    .unwrap_or("/var/lib/hik-f2b/state"),
            ),
            ignore,
            meta_id,
            log_filter,
            dry_run: boolean(g, "dry_run", false)?,
            // Not opened here: a missing or broken file only costs the
            // country, never the service (see `country`).
            country_db: g
                .get("country_db")
                .filter(|s| !s.is_empty())
                .map(PathBuf::from),
            inline_secrets: ini
                .values()
                .any(|sec| sec.contains_key("password") || sec.contains_key("bot_token")),
            mikrotik,
            nvrs,
            telegram,
        })
    }

    fn telegram(t: &Section) -> Result<TelegramCfg, String> {
        let token = secret(t, "bot_token", "telegram")?;
        let token_ok = match token.split_once(':') {
            Some((id, key)) => {
                !id.is_empty()
                    && id.chars().all(|c| c.is_ascii_digit())
                    && !key.is_empty()
                    && key
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            }
            None => false,
        };
        if !token_ok {
            return Err("telegram: bot_token does not look like a bot token".to_string());
        }
        let chat_id = required(t, "chat_id", "telegram")?.to_string();
        let digits = chat_id.strip_prefix('-').unwrap_or(&chat_id);
        let numeric =
            !digits.is_empty() && digits.len() <= 20 && digits.chars().all(|c| c.is_ascii_digit());
        let named = chat_id.len() > 1
            && chat_id.len() <= 64
            && chat_id.starts_with('@')
            && chat_id[1..]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !numeric && !named {
            return Err("telegram: chat_id must be a number or @channelname".to_string());
        }
        let thread_id = match t.get("message_thread_id").or_else(|| t.get("topic_id")) {
            Some(v) if !v.is_empty() => {
                Some(v.parse::<u64>().ok().filter(|n| *n > 0).ok_or_else(|| {
                    "telegram: message_thread_id must be a positive number".to_string()
                })?)
            }
            _ => None,
        };
        let message = t
            .get("message")
            .map(|s| s.as_str())
            .unwrap_or(DEFAULT_MESSAGE);
        if message.is_empty() || message.len() > 1000 {
            return Err("telegram: message is empty or too long".to_string());
        }
        Ok(TelegramCfg {
            api_url: check_url(
                t.get("api_url")
                    .map(|s| s.as_str())
                    .unwrap_or("https://api.telegram.org"),
                true,
                "telegram",
            )?,
            token,
            chat_id,
            thread_id,
            silent: boolean(t, "silent", false)?,
            health_alerts: boolean(t, "health_alerts", true)?,
            message: message.replace("\\n", "\n"),
        })
    }

    pub fn ignored(&self, ip: Ipv4Addr) -> bool {
        self.ignore.iter().any(|net| net.contains(ip))
    }
}

/// True when other local users can read the file (it may hold passwords).
#[cfg(unix)]
pub fn world_readable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o007 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
pub fn world_readable(_path: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "[mikrotik]\nurl = https://192.0.2.1\nuser = f2b\npassword = p\n\
                        ca_file = public\n\
                        [nvr:one]\nurl = http://192.0.2.10:8081\nuser = f2b\npassword = p\n";
    const NVR_ONLY: &str = "[nvr:one]\nurl = http://192.0.2.10:8081\nuser = f2b\npassword = p\n";

    #[test]
    fn defaults_and_minimal_config() {
        let cfg = Config::parse(BASE).unwrap();
        assert_eq!(cfg.maxretry, 5);
        let m = cfg.mikrotik.as_ref().unwrap();
        assert_eq!(m.address_list, "cctv_ban");
        assert_eq!(m.ca_file, None, "public roots");
        assert_eq!(cfg.nvrs.len(), 1);
        assert!(cfg.telegram.is_none());
        assert!(cfg.ignored("192.168.1.5".parse().unwrap()));
        assert!(!cfg.ignored("198.51.100.7".parse().unwrap()));
        assert!(cfg
            .log_filter
            .is_match("log.hikvision.com/Exception/illlegealAccess"));
        assert!(!cfg
            .log_filter
            .is_match("log.hikvision.com/Exception/videoLost/30"));
    }

    #[test]
    fn rejects_unsafe_settings() {
        let bad = |extra: &str, from: &str, to: &str| {
            Config::parse(&format!("{}{}", BASE.replace(from, to), extra)).is_err()
        };
        assert!(
            bad("", "https://192.0.2.1", "http://192.0.2.1"),
            "plain http to the router"
        );
        assert!(
            bad("", "https://192.0.2.1", "https://user@192.0.2.1"),
            "userinfo in url"
        );
        assert!(
            bad("", "https://192.0.2.1", "https://192.0.2.1/path"),
            "path in url"
        );
        assert!(
            bad(
                "",
                "https://192.0.2.1\nuser = f2b",
                "https://192.0.2.1\nuser = a:b"
            ),
            "colon in user"
        );
        assert!(bad("[general]\nmaxretry = 0\n", "", ""), "maxretry 0");
        assert!(
            bad("[general]\nmeta_id = a<b\n", "", ""),
            "markup in meta_id"
        );
        assert!(bad("[general]\nignoreip = banana\n", "", ""), "bad network");
        assert!(bad("[oops]\nx = 1\n", "", ""), "unknown section");
        assert!(
            bad("[telegram]\nbot_token = nonsense\nchat_id = 1\n", "", ""),
            "bad token"
        );
        assert!(
            bad("[telegram]\nbot_token = 1:a\nchat_id = 1; drop\n", "", ""),
            "bad chat id"
        );
        assert!(Config::parse(&BASE.replace("https://192.0.2.1", "http://127.0.0.1:8080")).is_ok());
        assert!(
            bad("", "ca_file = public\n", ""),
            "https router without ca_file"
        );
        assert!(
            bad("", "ca_file = public\n", "ca_file =\n"),
            "empty ca_file"
        );
        assert!(bad("[general]\nlookback = 0\n", "", ""), "lookback 0");
        assert!(bad("[general]\nlookback = 9\n", "", ""), "lookback 9");
        assert!(Config::parse(&format!("{}[general]\nlookback = 10\n", BASE)).is_ok());
        // a local plain-http router needs no CA
        assert!(Config::parse(
            &BASE
                .replace("https://192.0.2.1", "http://127.0.0.1:8080")
                .replace("ca_file = public\n", "")
        )
        .is_ok());
        let pinned = Config::parse(&BASE.replace("ca_file = public", "ca_file = /etc/ca.crt"))
            .unwrap()
            .mikrotik
            .unwrap();
        assert_eq!(pinned.ca_file, Some(PathBuf::from("/etc/ca.crt")));
    }

    #[test]
    fn router_is_optional() {
        let cfg = Config::parse(NVR_ONLY).unwrap();
        assert!(cfg.mikrotik.is_none());
        assert!(cfg.telegram.is_none());
        let cfg = Config::parse(&format!(
            "{}[telegram]\nbot_token = 1:a\nchat_id = 5\n",
            NVR_ONLY
        ))
        .unwrap();
        assert!(cfg.mikrotik.is_none());
        assert!(cfg.telegram.unwrap().message.contains("{action}"));
        // a [mikrotik] section that is present must still be complete
        assert!(Config::parse(&format!("{}[mikrotik]\nuser = f2b\n", NVR_ONLY)).is_err());
    }

    #[test]
    fn telegram_section() {
        let cfg = Config::parse(&format!(
            "{}[telegram]\nbot_token = 123:AbC_d-e\nchat_id = -1001234567890\nmessage_thread_id = 7\n",
            BASE
        ))
        .unwrap();
        let t = cfg.telegram.unwrap();
        assert_eq!(t.thread_id, Some(7));
        assert_eq!(t.api_url, "https://api.telegram.org");
        assert!(t.message.contains('\n'));
        let off = Config::parse(&format!("{}[telegram]\nenabled = false\n", BASE)).unwrap();
        assert!(off.telegram.is_none());
    }

    #[test]
    fn shipped_example_is_valid() {
        let example = include_str!("../hik-f2b.example.ini")
            .replace(
                "password_file = /run/secrets/hik-f2b-router",
                "password = a",
            )
            .replace("password_file = /run/secrets/hik-f2b-nvr", "password = b");
        let cfg = Config::parse(&example).unwrap();
        assert_eq!(cfg.nvrs.len(), 1);
        assert!(cfg.telegram.is_none());
        assert!(cfg.inline_secrets, "this test variant has inline passwords");
        assert_eq!(cfg.alert_after, 600);
        assert_eq!(cfg.country_db, None, "off unless set");
        let mikrotik = cfg.mikrotik.unwrap();
        assert_eq!(
            mikrotik.ca_file,
            Some(PathBuf::from("/etc/hik-f2b/router-ca.crt"))
        );
        assert!(mikrotik.check_rule);

        // the commented-out optional parts must be valid too
        let full: String = example
            .lines()
            .map(|l| l.strip_prefix(';').unwrap_or(l))
            .collect::<Vec<_>>()
            .join("\n")
            .replace(
                "bot_token_file    = /run/secrets/hik-f2b-telegram",
                "bot_token = 1:a",
            );
        let cfg = Config::parse(&full).unwrap();
        assert_eq!(cfg.nvrs.len(), 2);
        let telegram = cfg.telegram.unwrap();
        assert_eq!(telegram.thread_id, Some(42));
        assert!(telegram.message.contains('\n'));
        assert!(telegram.health_alerts);
        assert_eq!(
            cfg.country_db,
            Some(PathBuf::from("/etc/hik-f2b/country.mmdb"))
        );
    }

    #[test]
    fn country_db_setting() {
        assert_eq!(Config::parse(BASE).unwrap().country_db, None);
        assert_eq!(general("country_db =").unwrap().country_db, None);
        // a missing file is not a config error
        assert_eq!(
            general("country_db = /nonexistent/country.mmdb")
                .unwrap()
                .country_db,
            Some(PathBuf::from("/nonexistent/country.mmdb"))
        );
    }

    #[test]
    fn health_settings() {
        let cfg = Config::parse(&format!(
            "{}[telegram]\nbot_token = 1:a\nchat_id = 5\n",
            BASE
        ))
        .unwrap();
        assert_eq!(cfg.alert_after, 600);
        assert!(cfg.mikrotik.unwrap().check_rule);
        assert!(cfg.telegram.unwrap().health_alerts);

        let cfg = Config::parse(&format!(
            "{}[telegram]\nbot_token = 1:a\nchat_id = 5\nhealth_alerts = no\n\
             [general]\nalert_after = 30m\n",
            BASE.replace("ca_file = public\n", "ca_file = public\ncheck_rule = off\n")
        ))
        .unwrap();
        assert_eq!(cfg.alert_after, 1800);
        assert!(!cfg.mikrotik.unwrap().check_rule);
        assert!(!cfg.telegram.unwrap().health_alerts);

        assert!(general("alert_after = 1m").is_ok());
        assert!(general("alert_after = 59s").is_err());
        assert!(general("alert_after = 7d").is_ok());
        assert!(general("alert_after = 8d").is_err());
        assert!(general("alert_after = soon").is_err());
        let bad = Config::parse(&BASE.replace(
            "ca_file = public\n",
            "ca_file = public\ncheck_rule = maybe\n",
        ));
        assert!(bad.is_err());
    }

    fn general(lines: &str) -> Result<Config, String> {
        Config::parse(&format!("{}[general]\n{}\n", BASE, lines))
    }

    #[test]
    fn time_suffixes() {
        let cfg = general(
            "poll_interval = 1m\nfindtime = 2h\nbantime = 7d\nlookback = 90s\nauth_backoff = 15m",
        )
        .unwrap();
        assert_eq!(cfg.poll_interval, 60);
        assert_eq!(cfg.findtime, 7200);
        assert_eq!(cfg.bantime, BanTime::Seconds(7 * 86400));
        assert_eq!(cfg.lookback, 90);
        assert_eq!(cfg.auth_backoff, 900);
        assert_eq!(
            general("bantime = 2w").unwrap().bantime,
            BanTime::Seconds(14 * 86400)
        );
        // plain numbers keep meaning seconds
        let cfg = general("findtime = 600\nbantime = 3600").unwrap();
        assert_eq!(cfg.findtime, 600);
        assert_eq!(cfg.bantime, BanTime::Seconds(3600));
        assert_eq!(
            Config::parse(BASE).unwrap().bantime,
            BanTime::Seconds(86400)
        );
    }

    #[test]
    fn time_bounds_apply_after_conversion() {
        assert!(general("bantime = 1m").is_ok());
        assert!(general("bantime = 59s").is_err());
        // the longest timeout RouterOS accepts, 35w3d13h13m56s
        assert_eq!(
            general("bantime = 21474836").unwrap().bantime,
            BanTime::Seconds(21_474_836)
        );
        assert!(general("bantime = 248d").is_ok());
        assert!(general("bantime = 35w").is_ok());
        for long in ["21474837", "249d", "36w", "365d"] {
            let err = general(&format!("bantime = {}", long)).err().unwrap();
            assert!(
                err.contains("at most 21474836 seconds") && err.contains("bantime = permanent"),
                "{}: {}",
                long,
                err
            );
        }
        assert!(general("poll_interval = 1h").is_ok());
        assert!(general("poll_interval = 61m").is_err());
        assert!(general("lookback = 2d").is_ok());
        assert!(general("lookback = 49h").is_err());
        assert!(general("auth_backoff = 1d").is_ok());
        assert!(general("auth_backoff = 2d").is_err());
        assert!(general("findtime = 30d").is_ok());
        assert!(general("findtime = 5w").is_err());
        // too large for any integer type: a bounds error, not a panic
        let huge = general("bantime = 99999999999999999999w").err().unwrap();
        assert!(huge.contains("at most 21474836"), "{}", huge);
        let big = general("findtime = 3000000000000000000w").err().unwrap();
        assert!(big.contains("findtime must be between"), "{}", big);
    }

    #[test]
    fn bad_time_values() {
        for bad in [
            "10x", "-5m", "+5m", "+60", "1.5h", "", "m", "5mm", "10 m", "10M", "1e3", "0x10",
        ] {
            let err = general(&format!("findtime = {}", bad)).err();
            let err = err.unwrap_or_else(|| panic!("{:?} was accepted", bad));
            assert!(err.starts_with("findtime "), "{:?}: {}", bad, err);
        }
        let err = general("bantime = 10x").err().unwrap();
        assert!(
            err.starts_with("bantime ") && err.contains("permanent"),
            "{}",
            err
        );
        for key in [
            "poll_interval",
            "findtime",
            "lookback",
            "auth_backoff",
            "maxretry",
        ] {
            let err = general(&format!("{} = permanent", key)).err();
            let err = err.unwrap_or_else(|| panic!("{} = permanent was accepted", key));
            assert!(err.starts_with(key), "{}", err);
        }
    }

    #[test]
    fn permanent_bans() {
        assert_eq!(
            general("bantime = permanent").unwrap().bantime,
            BanTime::Permanent
        );
        assert_eq!(
            general("bantime = Permanent").unwrap().bantime,
            BanTime::Permanent
        );
        assert!(general("bantime = permanently").is_err());
        assert!(
            general("bantime = 0").is_err(),
            "0 is not a way to say permanent"
        );
    }

    #[test]
    fn networks() {
        let n = Net::parse("172.16.0.0/12").unwrap();
        assert!(n.contains("172.31.255.255".parse().unwrap()));
        assert!(!n.contains("172.32.0.0".parse().unwrap()));
        assert!(Net::parse("203.0.113.9")
            .unwrap()
            .contains("203.0.113.9".parse().unwrap()));
        assert!(Net::parse("0.0.0.0/0")
            .unwrap()
            .contains("8.8.8.8".parse().unwrap()));
        assert!(Net::parse("10.0.0.0/33").is_err());
    }
}
