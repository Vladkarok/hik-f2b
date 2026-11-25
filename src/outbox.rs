//! The outbox: notifications that wait to be sent to the chat.
//!
//! Notifications never hold up a ban: the engine queues them during a poll
//! and asks the outbox to send them at its end. The outbox decides what is
//! sent, sent again after a failure, dropped and logged.

use crate::action::{Notifier, NotifyError};
use std::sync::atomic::{AtomicBool, Ordering};

pub const MAX_QUEUED_NOTIFICATIONS: usize = 100;
pub const NOTIFY_ATTEMPTS: u32 = 5;
/// The longest wait for the messenger that is kept: one further away can
/// only come from the host clock having gone back.
pub const MAX_NOTIFY_WAIT: u64 = 3600;

pub struct Outbox {
    pub notifier: Option<Box<dyn Notifier>>,
    pub notifications: Vec<(String, u32)>,
    /// Notifications not queued in this cycle because the queue was full.
    pub dropped_notifications: usize,
    /// Host time before which the messenger asked not to be sent anything.
    pub notify_after: u64,
}

impl Outbox {
    pub fn new(notifier: Option<Box<dyn Notifier>>) -> Outbox {
        Outbox {
            notifier,
            notifications: Vec::new(),
            dropped_notifications: 0,
            notify_after: 0,
        }
    }

    /// Queues a message for the chat; counts it as dropped when
    /// `MAX_QUEUED_NOTIFICATIONS` already wait.
    pub fn queue_notification(&mut self, text: String) {
        if self.notifications.len() < MAX_QUEUED_NOTIFICATIONS {
            self.notifications.push((text, 0));
        } else {
            self.dropped_notifications += 1;
        }
    }

    /// Notifications never hold up a ban: they are sent afterwards and
    /// retried on later cycles if the messenger is unreachable. The first
    /// failure ends the attempt for this cycle, so an unreachable service
    /// costs at most one timeout per cycle. When the messenger asks to wait
    /// (too many messages), nothing is sent until then, and that wait is not
    /// a failed attempt.
    pub fn flush_notifications(&mut self, now: u64, stop: &AtomicBool) {
        if self.dropped_notifications > 0 {
            crate::warn!(
                "{} notification(s) dropped: {} already wait to be sent",
                self.dropped_notifications,
                MAX_QUEUED_NOTIFICATIONS
            );
            self.dropped_notifications = 0;
        }
        let Some(notifier) = &self.notifier else {
            self.notifications.clear();
            return;
        };
        if self.notify_after > now {
            if self.notify_after - now <= MAX_NOTIFY_WAIT {
                return;
            }
            self.notify_after = 0;
        }
        while let Some((text, attempts)) = self.notifications.first().cloned() {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match notifier.send(&text) {
                Ok(()) => {
                    crate::debug!("notification sent");
                    self.notifications.remove(0);
                }
                Err(NotifyError::RateLimited(wait)) => {
                    crate::info!(
                        "Telegram asks to wait {} s before the next message; {} notification(s) \
                         wait",
                        wait,
                        self.notifications.len()
                    );
                    self.notify_after = now.saturating_add(wait);
                    break;
                }
                Err(NotifyError::Failed(e)) => {
                    if attempts + 1 >= NOTIFY_ATTEMPTS {
                        crate::error!(
                            "notification dropped after {} attempts: {}",
                            NOTIFY_ATTEMPTS,
                            e
                        );
                        self.notifications.remove(0);
                    } else {
                        crate::warn!("notification failed, will retry: {}", e);
                        self.notifications[0].1 = attempts + 1;
                    }
                    break;
                }
            }
        }
    }
}
