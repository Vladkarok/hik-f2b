//! Small helpers: time, sanitising, encoding, logging.

use md5::{Digest, Md5};
use std::cell::RefCell;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static VERBOSE: AtomicBool = AtomicBool::new(false);
static COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn set_verbose(on: bool) {
    VERBOSE.store(on, Ordering::Relaxed);
}

pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One log line on stdout. Control characters are replaced so that text
/// taken from an NVR log can never forge or split a log line.
pub fn log(level: &str, msg: &str) {
    let clean: String = msg
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    CAPTURED.with(|captured| {
        if let Some(lines) = captured.borrow_mut().as_mut() {
            if lines.len() < MAX_CAPTURED {
                lines.push(format!("{} {}", level, clean));
            }
        }
    });
    let line = format!("{} {} {}\n", fmt_ts(unix_now() as i64), level, clean);
    let _ = std::io::stdout().lock().write_all(line.as_bytes());
}

const MAX_CAPTURED: usize = 10_000;

thread_local! {
    static CAPTURED: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
}

/// For tests: from now on also keep this thread's log lines (`LEVEL
/// message`, without the time) until `captured_log` takes them.
pub fn capture_log() {
    CAPTURED.with(|captured| *captured.borrow_mut() = Some(Vec::new()));
}

/// The lines kept since `capture_log` (which keeps going).
pub fn captured_log() -> Vec<String> {
    CAPTURED.with(|captured| {
        captured
            .borrow_mut()
            .as_mut()
            .map(std::mem::take)
            .unwrap_or_default()
    })
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Finds the first `YYYY-MM-DD[T ]HH:MM:SS` in the text that is a real date
/// from 1970 on and returns it as seconds. NVR timestamps are the device's
/// local wall clock, whatever suffix they carry; they are only ever compared
/// with each other and with the device's own clock, so the time zone never
/// matters. Dates that do not exist (`2026-02-31`) are not times. Neither
/// are times before 1970: the state file holds no negative time (see
/// `state::MAX_TIME` for the other end).
pub fn parse_ts(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    if b.len() < 19 {
        return None;
    }
    for i in 0..=b.len() - 19 {
        let w = &b[i..i + 19];
        let shaped = w.iter().enumerate().all(|(j, c)| match j {
            4 | 7 => *c == b'-',
            10 => *c == b'T' || *c == b' ',
            13 | 16 => *c == b':',
            _ => c.is_ascii_digit(),
        });
        if !shaped {
            continue;
        }
        let n = |a: usize, z: usize| -> i64 {
            w[a..z]
                .iter()
                .fold(0i64, |acc, c| acc * 10 + i64::from(c - b'0'))
        };
        let (y, mo, d) = (n(0, 4), n(5, 7), n(8, 10));
        let (h, mi, s) = (n(11, 13), n(14, 16), n(17, 19));
        if y < 1970
            || !(1..=12).contains(&mo)
            || !(1..=days_in_month(y, mo)).contains(&d)
            || h > 23
            || mi > 59
            || s > 60
        {
            continue;
        }
        let t = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s;
        if t > crate::state::MAX_TIME {
            // 9999-12-31T23:59:60
            continue;
        }
        return Some(t);
    }
    None
}

pub fn fmt_ts(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Seconds as a RouterOS time value, e.g. `1d00:00:00`.
pub fn fmt_timeout(seconds: u64) -> String {
    let seconds = seconds.max(1);
    let (days, rest) = (seconds / 86400, seconds % 86400);
    let hms = format!(
        "{:02}:{:02}:{:02}",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    );
    if days > 0 {
        format!("{}d{}", days, hms)
    } else {
        hms
    }
}

/// A name (of an NVR or an address-list): 1 to `max` letters, digits, `_`,
/// `-` and `.`.
pub fn is_name(text: &str, max: usize) -> bool {
    !text.is_empty()
        && text.len() <= max
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Printable ASCII only, at most `max` characters. For text that reaches the
/// router (address-list comments), HTTP headers, and the user name wherever
/// it is shown.
pub fn sanitize(text: &str, max: usize) -> String {
    text.chars()
        .take(max)
        .map(|c| if (' '..='~').contains(&c) { c } else { '?' })
        .collect()
}

/// Unicode characters that change how the text around them is shown
/// without being visible: line and paragraph separators, bidirectional
/// controls (which can make a line read differently from what it holds) and
/// zero-width characters.
fn invisible(c: char) -> bool {
    matches!(
        c,
        '\u{61c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
    )
}

/// At most `max` characters for the hik-f2b log or an error message for the
/// operator: control and invisible characters (`invisible`) become `?`,
/// other Unicode stays, so a path with Cyrillic letters is shown as it is. Not for text that reaches the router or an HTTP header: use
/// `sanitize` for that.
pub fn printable(text: &str, max: usize) -> String {
    text.chars()
        .take(max)
        .map(|c| {
            if c.is_control() || invisible(c) {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// Text for a terminal: keeps line structure (newline, tab) but replaces
/// every other control character, so raw NVR replies printed by `--dump
/// --raw` cannot carry escape sequences or carriage returns that rewrite
/// what is on screen.
pub fn terminal_safe(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '?'
            } else {
                c
            }
        })
        .collect()
}

pub fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub fn b64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

pub fn md5_hex(text: &str) -> String {
    Md5::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// 16 hex characters that are hard to predict. Used for the digest client
/// nonce and search ids, neither of which is a secret.
pub fn random_hex() -> String {
    let mut buf = [0u8; 8];
    let ok = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok();
    if ok {
        return buf.iter().map(|b| format!("{:02x}", b)).collect();
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    md5_hex(&format!("{}:{}:{}", nanos, n, std::process::id()))[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps() {
        let t = parse_ts("2026-11-18T20:14:25+02:00").unwrap();
        assert_eq!(fmt_ts(t), "2026-11-18T20:14:25Z");
        assert_eq!(
            parse_ts("x 2024-02-29 23:59:59 y").map(fmt_ts).unwrap(),
            "2024-02-29T23:59:59Z"
        );
        assert_eq!(fmt_ts(0), "1970-01-01T00:00:00Z");
        assert_eq!(parse_ts("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_ts("2026-13-01T00:00:00"), None);
        assert_eq!(parse_ts("no time here"), None);
        assert_eq!(
            parse_ts("2026-11-18T20:14:25").unwrap() - parse_ts("2026-11-17T20:14:25").unwrap(),
            86400
        );
    }

    #[test]
    fn impossible_and_early_dates_are_not_times() {
        for text in [
            "2026-02-29T00:00:00",
            "2026-02-31T00:00:00",
            "2026-04-31T00:00:00",
            "1900-02-29T00:00:00",
            "2026-00-10T00:00:00",
            "2026-01-00T00:00:00",
            "2026-01-10T24:00:00",
            "1969-12-31T23:59:59",
            "0000-01-01T00:00:00",
            "9999-12-31T23:59:60",
        ] {
            assert_eq!(parse_ts(text), None, "{}", text);
        }
        for (text, shown) in [
            ("2024-02-29T12:00:00", "2024-02-29T12:00:00Z"),
            ("2000-02-29T12:00:00", "2000-02-29T12:00:00Z"),
            ("2026-04-30T23:59:59", "2026-04-30T23:59:59Z"),
            ("2026-12-31T23:59:59", "2026-12-31T23:59:59Z"),
            ("9999-12-31T23:59:59", "9999-12-31T23:59:59Z"),
        ] {
            assert_eq!(
                parse_ts(text).map(fmt_ts).as_deref(),
                Some(shown),
                "{}",
                text
            );
        }
        assert_eq!(
            parse_ts("9999-12-31T23:59:59"),
            Some(crate::state::MAX_TIME)
        );
        // an impossible date is passed over, the next real one is found
        assert_eq!(
            parse_ts("2026-02-30T10:00:00 / 2026-03-01T10:00:00").map(fmt_ts),
            Some("2026-03-01T10:00:00Z".to_string())
        );
        // a leap second is the next second
        assert_eq!(
            parse_ts("2026-06-30T23:59:60"),
            parse_ts("2026-07-01T00:00:00")
        );
    }

    #[test]
    fn printable_keeps_unicode_but_not_controls() {
        let path = "/srv/\u{43a}\u{430}\u{43c}\u{435}\u{440}\u{438}/hik-f2b.ini";
        assert_eq!(printable(path, 300), path);
        assert_eq!(sanitize(path, 300), "/srv/??????/hik-f2b.ini");
        assert_eq!(
            printable("a\nb\r\u{1b}[2J\u{7f}\u{9b}c\t", 100),
            "a?b??[2J??c?"
        );
        // bidirectional, zero-width and line-separator characters
        assert_eq!(
            printable("x\u{202e}y\u{2066}z\u{200b}w\u{2028}v\u{feff}u\u{61c}", 100),
            "x?y?z?w?v?u?"
        );
        assert_eq!(printable("\u{442}\u{442}\u{442}", 2), "\u{442}\u{442}");
    }

    #[test]
    fn timeouts() {
        assert_eq!(fmt_timeout(60), "00:01:00");
        assert_eq!(fmt_timeout(86400), "1d00:00:00");
        assert_eq!(fmt_timeout(7 * 86400 + 3661), "7d01:01:01");
    }

    #[test]
    fn encodings() {
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"f"), "Zg==");
        assert_eq!(b64(b"fo"), "Zm8=");
        assert_eq!(b64(b"foobar"), "Zm9vYmFy");
        assert_eq!(md5_hex(""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(json_escape("a\"b\\c\n"), "a\\\"b\\\\c\\u000a");
        assert_eq!(sanitize("ab\ncd\u{442}efgh", 7), "ab?cd?e");
        assert_eq!(random_hex().len(), 16);
        assert_eq!(
            terminal_safe("a\n\tb\r\u{1b}[2Jc\u{7f}\u{9b}d\u{442}"),
            "a\n\tb??[2Jc??d\u{442}"
        );
    }
}
