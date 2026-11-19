//! hik-f2b: fail2ban-style banning for Hikvision NVRs behind a MikroTik.
//!
//! Polls the NVR log over ISAPI for failed logins, counts them per source
//! address and, once an address reaches `maxretry` failures within
//! `findtime`, adds it to a firewall address-list on the router through the
//! RouterOS REST API, with a timeout of `bantime` or, for a permanent ban,
//! as a static entry. Without a router it runs in notify-only mode and just
//! reports such addresses.
//!
//! Everything read from an NVR log is attacker-influenced (the user name is
//! whatever the attacker typed). It is parsed strictly, length-limited and
//! sanitised before it reaches a log line, the router or Telegram.

#![forbid(unsafe_code)]

#[macro_export]
macro_rules! info {
    ($($a:tt)*) => { $crate::util::log("INFO", &format!($($a)*)) };
}
#[macro_export]
macro_rules! warn {
    ($($a:tt)*) => { $crate::util::log("WARNING", &format!($($a)*)) };
}
#[macro_export]
macro_rules! error {
    ($($a:tt)*) => { $crate::util::log("ERROR", &format!($($a)*)) };
}
#[macro_export]
macro_rules! debug {
    ($($a:tt)*) => {
        if $crate::util::verbose() {
            $crate::util::log("DEBUG", &format!($($a)*))
        }
    };
}

pub mod action;
pub mod config;
pub mod engine;
pub mod health;
pub mod http;
pub mod mikrotik;
pub mod nvr;
pub mod state;
pub mod telegram;
pub mod util;
