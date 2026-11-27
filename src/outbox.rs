//! The outbox: the notifications that wait to be sent to the chat.
//!
//! Notifications never hold up a ban: the engine queues their texts during a
//! poll and, at its end, asks the outbox to send what it can at that host
//! time. The outbox decides what is sent, tried again on a later poll,
//! dropped and logged. It knows nothing of bans or health checks: a text is
//! a text.

use crate::action::{Notifier, NotifyError};
use std::sync::atomic::{AtomicBool, Ordering};

/// The most notifications that wait; more are dropped and counted.
const MAX_QUEUED_NOTIFICATIONS: usize = 100;
/// How often a notification is tried before it is dropped.
const NOTIFY_ATTEMPTS: u32 = 5;
/// The longest wait for the messenger that is kept: one further away can
/// only come from the host clock having gone back.
const MAX_NOTIFY_WAIT: u64 = 3600;

pub struct Outbox {
    notifier: Option<Box<dyn Notifier>>,
    /// The texts in the order they were queued, each with its failed
    /// attempts so far.
    queue: Vec<(String, u32)>,
    /// Notifications not queued since the last `send` because the queue
    /// was full.
    dropped: usize,
    /// Host time before which the messenger asked not to be sent anything.
    send_after: u64,
}

impl Outbox {
    /// An outbox that sends through `notifier`. Without one it keeps
    /// nothing.
    pub fn new(notifier: Option<Box<dyn Notifier>>) -> Outbox {
        Outbox {
            notifier,
            queue: Vec::new(),
            dropped: 0,
            send_after: 0,
        }
    }

    /// Queues a text for the chat; counts it as dropped when
    /// `MAX_QUEUED_NOTIFICATIONS` already wait. Without a notifier the text
    /// is not kept.
    pub fn queue(&mut self, text: String) {
        if self.notifier.is_none() {
            return;
        }
        if self.queue.len() < MAX_QUEUED_NOTIFICATIONS {
            self.queue.push((text, 0));
        } else {
            self.dropped += 1;
        }
    }

    /// How many notifications wait to be sent.
    pub fn waiting(&self) -> usize {
        self.queue.len()
    }

    /// Sends what can be sent at `host_now`, oldest first, and first logs
    /// how many notifications were dropped because the queue was full. The
    /// first failure ends the attempts of this poll, so an unreachable
    /// messenger costs at most one timeout per poll; a notification is
    /// dropped after `NOTIFY_ATTEMPTS`. When the messenger asks to wait (too
    /// many messages), nothing is sent until then, and that wait is not a
    /// failed attempt. `stop` is looked at before each send. Returns
    /// whether the stop left notifications waiting.
    pub fn send(&mut self, host_now: u64, stop: &AtomicBool) -> bool {
        if self.dropped > 0 {
            crate::warn!(
                "{} notification(s) dropped: {} already wait to be sent",
                self.dropped,
                MAX_QUEUED_NOTIFICATIONS
            );
            self.dropped = 0;
        }
        let Some(notifier) = &self.notifier else {
            self.queue.clear();
            return false;
        };
        if self.send_after > host_now {
            if self.send_after - host_now <= MAX_NOTIFY_WAIT {
                return false;
            }
            self.send_after = 0;
        }
        while let Some((text, attempts)) = self.queue.first().cloned() {
            if stop.load(Ordering::Relaxed) {
                return true;
            }
            match notifier.send(&text) {
                Ok(()) => {
                    crate::debug!("notification sent");
                    self.queue.remove(0);
                }
                Err(NotifyError::RateLimited(wait)) => {
                    crate::info!(
                        "Telegram asks to wait {} s before the next message; {} notification(s) \
                         wait",
                        wait,
                        self.queue.len()
                    );
                    self.send_after = host_now.saturating_add(wait);
                    break;
                }
                Err(NotifyError::Failed(e)) => {
                    if attempts + 1 >= NOTIFY_ATTEMPTS {
                        crate::error!(
                            "notification dropped after {} attempts: {}",
                            NOTIFY_ATTEMPTS,
                            e
                        );
                        self.queue.remove(0);
                    } else {
                        crate::warn!("notification failed, will retry: {}", e);
                        self.queue[0].1 = attempts + 1;
                    }
                    break;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{self, capture_log, captured_log};
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;
    use std::sync::Arc;

    /// What the recorder was given and how it is to answer.
    #[derive(Default)]
    struct Tape {
        /// Every text it was asked to send, in order, also those it failed.
        tried: Vec<String>,
        /// The answers to give, in order; `Ok` once they run out.
        answers: VecDeque<Result<(), NotifyError>>,
        /// Set after this many sends, as a signal handler would.
        stop_after: Option<(usize, Arc<AtomicBool>)>,
    }

    /// The in-memory `Notifier` (ADR 0002): it records what it is given and
    /// answers from its tape.
    struct Recorder(Rc<RefCell<Tape>>);

    impl Notifier for Recorder {
        fn send(&self, text: &str) -> Result<(), NotifyError> {
            let mut tape = self.0.borrow_mut();
            tape.tried.push(text.to_string());
            if let Some((n, stop)) = &tape.stop_after {
                if tape.tried.len() >= *n {
                    stop.store(true, Ordering::Relaxed);
                }
            }
            tape.answers.pop_front().unwrap_or(Ok(()))
        }
    }

    const T: u64 = 1_768_039_200;

    struct Run {
        outbox: Outbox,
        tape: Rc<RefCell<Tape>>,
        stop: Arc<AtomicBool>,
    }

    impl Run {
        fn new() -> Run {
            // the DEBUG line of a sent notification is checked too
            util::set_verbose(true);
            capture_log();
            let tape = Rc::new(RefCell::new(Tape::default()));
            Run {
                outbox: Outbox::new(Some(Box::new(Recorder(Rc::clone(&tape))))),
                tape,
                stop: Arc::new(AtomicBool::new(false)),
            }
        }

        fn queue(&mut self, texts: &[&str]) {
            for text in texts {
                self.outbox.queue(text.to_string());
            }
        }

        fn answer(&self, answers: Vec<Result<(), NotifyError>>) {
            self.tape.borrow_mut().answers.extend(answers);
        }

        /// One `send` at `host_now`: what was tried and what was logged.
        fn send(&mut self, host_now: u64) -> (Vec<String>, Vec<String>) {
            self.outbox.send(host_now, &self.stop);
            let tried = std::mem::take(&mut self.tape.borrow_mut().tried);
            (tried, captured_log())
        }
    }

    fn failed(e: &str) -> Result<(), NotifyError> {
        Err(NotifyError::Failed(e.to_string()))
    }

    fn texts(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    #[test]
    fn sends_in_the_order_queued() {
        let mut r = Run::new();
        r.queue(&["a", "b", "c"]);
        assert_eq!(r.outbox.waiting(), 3);
        let (tried, log) = r.send(T);
        assert_eq!(tried, texts(&["a", "b", "c"]));
        assert_eq!(log, texts(&["DEBUG notification sent"; 3]));
        assert_eq!(r.outbox.waiting(), 0);
        // nothing is sent twice
        let (tried, log) = r.send(T + 60);
        assert!(tried.is_empty() && log.is_empty());
        // queued after a send: sent at the next
        r.queue(&["d"]);
        assert_eq!(r.send(T + 120).0, texts(&["d"]));
    }

    #[test]
    fn the_first_failure_ends_the_attempts_of_this_poll() {
        let mut r = Run::new();
        r.queue(&["a", "b", "c"]);
        r.answer(vec![Ok(()), failed("HTTP 502: bad gateway")]);
        let (tried, log) = r.send(T);
        assert_eq!(tried, texts(&["a", "b"]), "c is not tried after b failed");
        assert_eq!(
            log,
            texts(&[
                "DEBUG notification sent",
                "WARNING notification failed, will retry: HTTP 502: bad gateway",
            ])
        );
        assert_eq!(r.outbox.waiting(), 2);
        // the next poll starts again with the one that failed
        let (tried, _) = r.send(T + 60);
        assert_eq!(tried, texts(&["b", "c"]));
        assert_eq!(r.outbox.waiting(), 0);
    }

    #[test]
    fn a_notification_is_dropped_after_its_last_attempt() {
        let mut r = Run::new();
        r.queue(&["a", "b"]);
        r.answer((0..NOTIFY_ATTEMPTS).map(|_| failed("timed out")).collect());
        for i in 1..NOTIFY_ATTEMPTS {
            let (tried, log) = r.send(T + u64::from(i) * 60);
            assert_eq!(tried, texts(&["a"]), "attempt {}", i);
            assert_eq!(
                log,
                texts(&["WARNING notification failed, will retry: timed out"])
            );
            assert_eq!(r.outbox.waiting(), 2);
        }
        let (tried, log) = r.send(T + 3600);
        assert_eq!(
            tried,
            texts(&["a"]),
            "a failure ends the poll, also this one"
        );
        assert_eq!(
            log,
            texts(&["ERROR notification dropped after 5 attempts: timed out"])
        );
        assert_eq!(r.outbox.waiting(), 1);
        // b has its own attempts
        let (tried, log) = r.send(T + 3660);
        assert_eq!(tried, texts(&["b"]));
        assert_eq!(log, texts(&["DEBUG notification sent"]));
        assert_eq!(r.outbox.waiting(), 0);
    }

    #[test]
    fn a_wait_the_messenger_asks_for_is_not_a_failed_attempt() {
        let mut r = Run::new();
        r.queue(&["a", "b"]);
        r.answer(vec![Ok(()), Err(NotifyError::RateLimited(30))]);
        let (tried, log) = r.send(T);
        assert_eq!(tried, texts(&["a", "b"]));
        assert_eq!(
            log,
            texts(&[
                "DEBUG notification sent",
                "INFO Telegram asks to wait 30 s before the next message; 1 notification(s) wait",
            ])
        );
        // nothing is sent before the wait ends, not even what is new
        r.queue(&["c"]);
        for at in [T, T + 1, T + 29] {
            let (tried, log) = r.send(at);
            assert!(tried.is_empty() && log.is_empty(), "at T + {}", at - T);
        }
        assert_eq!(r.outbox.waiting(), 2);
        let (tried, _) = r.send(T + 30);
        assert_eq!(tried, texts(&["b", "c"]));
        // more waits than attempts: a notification that waits is never
        // dropped, and its failed attempts still count from zero
        r.queue(&["d"]);
        let mut at = T + 60;
        for _ in 0..2 * NOTIFY_ATTEMPTS {
            r.answer(vec![Err(NotifyError::RateLimited(10))]);
            assert_eq!(r.send(at).0, texts(&["d"]));
            at += 10;
        }
        r.answer((1..NOTIFY_ATTEMPTS).map(|_| failed("down")).collect());
        for _ in 1..NOTIFY_ATTEMPTS {
            assert_eq!(r.send(at).0, texts(&["d"]));
            at += 60;
        }
        assert_eq!(r.outbox.waiting(), 1, "4 failed attempts after the waits");
        r.answer(vec![failed("down")]);
        let (_, log) = r.send(at);
        assert_eq!(
            log,
            texts(&["ERROR notification dropped after 5 attempts: down"])
        );
        assert_eq!(r.outbox.waiting(), 0);
    }

    #[test]
    fn a_wait_further_away_than_an_hour_is_not_kept() {
        // up to an hour is kept
        let mut r = Run::new();
        r.queue(&["a"]);
        r.answer(vec![Err(NotifyError::RateLimited(MAX_NOTIFY_WAIT))]);
        r.send(T);
        assert!(r.send(T).0.is_empty());
        assert!(r.send(T + MAX_NOTIFY_WAIT - 1).0.is_empty());
        assert_eq!(r.send(T + MAX_NOTIFY_WAIT).0, texts(&["a"]));
        // a longer one is dropped when a send finds it more than an hour
        // away, and that send goes ahead
        r.queue(&["b"]);
        r.answer(vec![Err(NotifyError::RateLimited(MAX_NOTIFY_WAIT + 1))]);
        let at = T + 7200;
        r.send(at);
        assert!(r.send(at + 1).0.is_empty(), "an hour away is kept");
        assert_eq!(r.send(at).0, texts(&["b"]), "more than an hour away");
        assert_eq!(r.outbox.waiting(), 0);
    }

    #[test]
    fn a_wait_after_the_host_clock_went_back() {
        let mut r = Run::new();
        r.queue(&["a"]);
        r.answer(vec![Err(NotifyError::RateLimited(30))]);
        r.send(T);
        // back by less than an hour: the wait still ends at T + 30
        assert!(r.send(T - 600).0.is_empty());
        // back by more: the wait is forgotten
        let (tried, log) = r.send(T - 3600);
        assert_eq!(tried, texts(&["a"]));
        assert_eq!(log, texts(&["DEBUG notification sent"]));
        // and does not come back once the clock is right again
        r.queue(&["b"]);
        assert_eq!(r.send(T + 1).0, texts(&["b"]));
    }

    #[test]
    fn a_full_queue_drops_and_counts_what_does_not_fit() {
        let mut r = Run::new();
        let names: Vec<String> = (0..MAX_QUEUED_NOTIFICATIONS + 5)
            .map(|i| format!("n{}", i))
            .collect();
        for name in &names {
            r.outbox.queue(name.clone());
        }
        assert_eq!(r.outbox.waiting(), MAX_QUEUED_NOTIFICATIONS);
        r.answer(vec![Ok(()), failed("down")]);
        let (tried, log) = r.send(T);
        // the first ones are kept, the last ones dropped
        assert_eq!(tried, names[..2].to_vec());
        assert_eq!(
            log,
            texts(&[
                "WARNING 5 notification(s) dropped: 100 already wait to be sent",
                "DEBUG notification sent",
                "WARNING notification failed, will retry: down",
            ])
        );
        assert_eq!(r.outbox.waiting(), MAX_QUEUED_NOTIFICATIONS - 1);
        // the count is logged once
        r.answer(vec![failed("down")]);
        let (_, log) = r.send(T + 60);
        assert_eq!(
            log,
            texts(&["WARNING notification failed, will retry: down"])
        );
        // with room again, a new one is queued; then the queue is full again
        r.queue(&["new", "too many", "and more"]);
        assert_eq!(r.outbox.waiting(), MAX_QUEUED_NOTIFICATIONS);
        r.answer(vec![Err(NotifyError::RateLimited(600))]);
        let (tried, log) = r.send(T + 120);
        assert_eq!(tried, texts(&["n1"]));
        assert_eq!(
            log,
            texts(&[
                "WARNING 2 notification(s) dropped: 100 already wait to be sent",
                "INFO Telegram asks to wait 600 s before the next message; 100 notification(s) \
                 wait",
            ])
        );
        // the count is logged while the messenger asks to wait, too
        r.queue(&["one more"]);
        let (tried, log) = r.send(T + 180);
        assert!(tried.is_empty());
        assert_eq!(
            log,
            texts(&["WARNING 1 notification(s) dropped: 100 already wait to be sent"])
        );
        let (tried, log) = r.send(T + 720);
        assert_eq!(tried.len(), MAX_QUEUED_NOTIFICATIONS);
        assert_eq!((&tried[0][..], &tried[99][..]), ("n1", "new"));
        assert_eq!(
            log,
            texts(&["DEBUG notification sent"; MAX_QUEUED_NOTIFICATIONS])
        );
        assert_eq!(r.outbox.waiting(), 0);
    }

    #[test]
    fn a_stop_ends_the_sending_between_two_sends() {
        let mut r = Run::new();
        r.queue(&["a", "b", "c"]);
        r.tape.borrow_mut().stop_after = Some((1, Arc::clone(&r.stop)));
        let (tried, log) = r.send(T);
        assert_eq!(tried, texts(&["a"]), "the send under way ends, no other");
        assert_eq!(log, texts(&["DEBUG notification sent"]));
        assert_eq!(r.outbox.waiting(), 2);
        // while the flag is set nothing is sent and nothing is lost
        let (tried, log) = r.send(T + 60);
        assert!(tried.is_empty() && log.is_empty());
        assert_eq!(r.outbox.waiting(), 2);
        r.tape.borrow_mut().stop_after = None;
        r.stop.store(false, Ordering::Relaxed);
        assert_eq!(r.send(T + 120).0, texts(&["b", "c"]));
    }

    #[test]
    fn a_stop_during_the_last_send_leaves_nothing_waiting() {
        let mut r = Run::new();
        r.queue(&["a"]);
        r.tape.borrow_mut().stop_after = Some((1, Arc::clone(&r.stop)));
        assert!(!r.outbox.send(T, &r.stop), "nothing was left waiting");
        r.stop.store(false, Ordering::Relaxed);
        r.queue(&["b", "c"]);
        r.tape.borrow_mut().stop_after = Some((1, Arc::clone(&r.stop)));
        assert!(r.outbox.send(T + 60, &r.stop), "c waits");
        assert_eq!(r.outbox.waiting(), 1);
    }

    #[test]
    fn without_a_notifier_nothing_is_kept() {
        capture_log();
        let stop = AtomicBool::new(false);
        let mut outbox = Outbox::new(None);
        for i in 0..MAX_QUEUED_NOTIFICATIONS + 5 {
            outbox.queue(format!("n{}", i));
        }
        assert_eq!(outbox.waiting(), 0);
        outbox.send(T, &stop);
        assert_eq!(outbox.waiting(), 0);
        assert!(
            captured_log().is_empty(),
            "not even a count of dropped ones"
        );
    }
}
