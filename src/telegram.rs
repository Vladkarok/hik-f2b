//! Optional Telegram notifications about detections and bans.
//!
//! The bot token is part of the request URL, and HTTP client errors quote
//! URLs, so every error message leaving this module is redacted.

use crate::action::{Notifier, NotifyError};
use crate::config::TelegramCfg;
use crate::{http, util};
use std::time::Duration;

/// A notification is never worth holding up the poll loop for long.
const TIMEOUT: Duration = Duration::from_secs(10);
/// The wait after HTTP 429 when the answer does not say how long, and the
/// longest wait taken from an answer.
const DEFAULT_RETRY_AFTER: u64 = 30;
const MAX_RETRY_AFTER: u64 = 3600;

/// The seconds to wait from a Telegram 429 answer: the `retry_after`
/// parameter of the body (`"parameters":{"retry_after":5}`), else the
/// `Retry-After` header, else `DEFAULT_RETRY_AFTER`; at least 1, at most
/// `MAX_RETRY_AFTER`.
fn retry_after(header: Option<&str>, body: &str) -> u64 {
    let from_body = body.find("\"retry_after\"").and_then(|at| {
        let rest = body[at + "\"retry_after\"".len()..].trim_start();
        let rest = rest.strip_prefix(':')?.trim_start();
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse::<u64>().ok()
    });
    let from_header = header.and_then(|h| h.trim().parse::<u64>().ok());
    from_body
        .or(from_header)
        .unwrap_or(DEFAULT_RETRY_AFTER)
        .clamp(1, MAX_RETRY_AFTER)
}

pub struct Telegram {
    url: String,
    token: String,
    chat_id: String,
    thread_id: Option<String>,
    silent: bool,
    agent: ureq::Agent,
}

impl Telegram {
    pub fn new(cfg: &TelegramCfg) -> Result<Telegram, String> {
        Ok(Telegram {
            url: format!("{}/bot{}/sendMessage", cfg.api_url, cfg.token),
            token: cfg.token.clone(),
            chat_id: cfg.chat_id.clone(),
            thread_id: cfg.thread_id.map(|n| n.to_string()),
            silent: cfg.silent,
            agent: http::agent(&cfg.api_url, None, TIMEOUT)
                .map_err(|e| format!("telegram: {}", e))?,
        })
    }

    fn redact(&self, text: &str) -> String {
        util::sanitize(&text.replace(&self.token, "<token>"), 200)
    }
}

impl Notifier for Telegram {
    /// The text is sent without a parse mode, so nothing in it (including
    /// the user name an attacker typed) is interpreted as markup.
    fn send(&self, text: &str) -> Result<(), NotifyError> {
        let text: String = text.chars().take(1000).collect();
        let mut form: Vec<(&str, &str)> =
            vec![("chat_id", self.chat_id.as_str()), ("text", text.as_str())];
        if let Some(thread) = &self.thread_id {
            form.push(("message_thread_id", thread.as_str()));
        }
        if self.silent {
            form.push(("disable_notification", "true"));
        }
        match self.agent.post(&self.url).send_form(&form) {
            Ok(resp) if resp.status() == 200 => Ok(()),
            Ok(resp) => Err(NotifyError::Failed(format!(
                "unexpected HTTP {}",
                resp.status()
            ))),
            Err(ureq::Error::Status(429, resp)) => {
                let header = resp.header("Retry-After").map(str::to_string);
                let detail = http::read_body(resp, 64 * 1024).unwrap_or_default();
                Err(NotifyError::RateLimited(retry_after(
                    header.as_deref(),
                    &detail,
                )))
            }
            Err(ureq::Error::Status(code, resp)) => {
                let detail = http::read_body(resp, 64 * 1024).unwrap_or_default();
                Err(NotifyError::Failed(format!(
                    "HTTP {}: {}",
                    code,
                    self.redact(&detail)
                )))
            }
            Err(e) => Err(NotifyError::Failed(self.redact(&e.to_string()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::retry_after;

    #[test]
    fn reads_how_long_to_wait() {
        // the body of a Telegram 429 answer
        let body = r#"{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 7","parameters":{"retry_after":7}}"#;
        assert_eq!(retry_after(None, body), 7);
        assert_eq!(retry_after(Some("12"), body), 7, "the body first");
        assert_eq!(retry_after(Some(" 12 "), "{}"), 12);
        assert_eq!(retry_after(None, "{\"retry_after\" : 3}"), 3);
        assert_eq!(retry_after(None, "not json"), 30);
        assert_eq!(retry_after(Some("soon"), ""), 30);
        assert_eq!(retry_after(None, "{\"retry_after\":0}"), 1);
        assert_eq!(retry_after(None, "{\"retry_after\":999999999}"), 3600);
        assert_eq!(
            retry_after(None, "{\"retry_after\":99999999999999999999999}"),
            30
        );
    }
}
