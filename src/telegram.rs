//! Optional Telegram notifications about detections and bans.
//!
//! The bot token is part of the request URL, and HTTP client errors quote
//! URLs, so every error message leaving this module is redacted.

use crate::action::Notifier;
use crate::config::TelegramCfg;
use crate::{http, util};
use std::time::Duration;

/// A notification is never worth holding up the poll loop for long.
const TIMEOUT: Duration = Duration::from_secs(10);

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
    fn send(&self, text: &str) -> Result<(), String> {
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
            Ok(resp) => Err(format!("unexpected HTTP {}", resp.status())),
            Err(ureq::Error::Status(code, resp)) => {
                let detail = http::read_body(resp, 64 * 1024).unwrap_or_default();
                Err(format!("HTTP {}: {}", code, self.redact(&detail)))
            }
            Err(e) => Err(self.redact(&e.to_string())),
        }
    }
}
