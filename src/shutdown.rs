//! Shutdown coordination with a two-stage signal protocol.
//!
//! - First SIGTERM/SIGINT begins a *drain*: listeners stop accepting new
//!   connections, in-flight requests are allowed up to `drain_grace_seconds`
//!   to finish, then the proxy exits cleanly.
//! - A second signal during drain triggers *force-exit*: pending connections
//!   are aborted rather than waited on, and the process exits immediately.
//!
//! Internally this is two `tokio::sync::watch` channels so every spawned task
//! can `select!` on the signal state without polling. A third signal (after
//! force) is left to the OS default — by then, an impatient operator
//! probably wants the kernel to take over.

use std::sync::Arc;
use std::time::Duration;

use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;

/// Why the proxy is exiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    /// Drain was triggered (SIGTERM/SIGINT or programmatic) and the
    /// configured `drain_grace_seconds` elapsed normally.
    DrainComplete,
    /// A second signal arrived while we were waiting for drain — operator
    /// asked us to skip the rest of the grace period and bail out now.
    Forced,
}

#[derive(Clone)]
pub struct Coordinator {
    drain_tx: Arc<watch::Sender<bool>>,
    drain_rx: watch::Receiver<bool>,
    force_tx: Arc<watch::Sender<bool>>,
    force_rx: watch::Receiver<bool>,
    drain_grace: Duration,
}

impl Coordinator {
    pub fn new(drain_grace_seconds: u64) -> Self {
        let (drain_tx, drain_rx) = watch::channel(false);
        let (force_tx, force_rx) = watch::channel(false);
        Self {
            drain_tx: Arc::new(drain_tx),
            drain_rx,
            force_tx: Arc::new(force_tx),
            force_rx,
            drain_grace: Duration::from_secs(drain_grace_seconds),
        }
    }

    pub fn is_draining(&self) -> bool {
        *self.drain_rx.borrow()
    }

    pub fn is_forcing(&self) -> bool {
        *self.force_rx.borrow()
    }

    pub fn drain_grace(&self) -> Duration {
        self.drain_grace
    }

    /// Trigger drain manually (used by tests and the SIGTERM/SIGINT handler).
    pub fn trigger_drain(&self) {
        let _ = self.drain_tx.send(true);
    }

    /// Trigger an immediate force-exit. Aborts the rest of the drain grace
    /// period and causes per-connection tasks to drop their connections
    /// instead of waiting for `drain_grace`.
    pub fn trigger_force(&self) {
        let _ = self.force_tx.send(true);
    }

    pub fn install_signal_handlers(&self) {
        let drain_tx = self.drain_tx.clone();
        let force_tx = self.force_tx.clone();
        tokio::spawn(async move {
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "failed to install SIGTERM handler");
                    return;
                }
            };
            let mut sigint = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "failed to install SIGINT handler");
                    return;
                }
            };

            // First signal: graceful drain.
            tokio::select! {
                _ = sigterm.recv() => tracing::info!("received SIGTERM, beginning drain"),
                _ = sigint.recv()  => tracing::info!("received SIGINT, beginning drain (send again to force-exit)"),
            }
            let _ = drain_tx.send(true);

            // Second signal: force exit. The signal-handler task only runs
            // through this section once and then returns — a *third* signal
            // is the OS default behaviour (which, by the time we get here,
            // is probably what an impatient operator actually wants).
            tokio::select! {
                _ = sigterm.recv() => tracing::warn!(
                    "received SIGTERM again — forcing immediate shutdown, in-flight requests will be aborted"
                ),
                _ = sigint.recv()  => tracing::warn!(
                    "received SIGINT again — forcing immediate shutdown, in-flight requests will be aborted"
                ),
            }
            let _ = force_tx.send(true);
        });
    }

    /// Returns as soon as drain has been triggered (immediately if already draining).
    pub async fn wait_for_drain_start(&self) {
        let mut rx = self.drain_rx.clone();
        if *rx.borrow() {
            return;
        }
        let _ = rx.changed().await;
    }

    /// Returns as soon as force shutdown has been triggered.
    pub async fn wait_for_force(&self) {
        let mut rx = self.force_rx.clone();
        if *rx.borrow() {
            return;
        }
        let _ = rx.changed().await;
    }

    /// Block until the proxy should exit. Returns the reason — drain
    /// completed normally vs operator-forced.
    pub async fn wait_for_exit(&self) -> ExitReason {
        self.wait_for_drain_start().await;
        tokio::select! {
            _ = tokio::time::sleep(self.drain_grace) => ExitReason::DrainComplete,
            _ = self.wait_for_force() => ExitReason::Forced,
        }
    }

    /// Compatibility shim — preserves the older `wait_for_drain()` signature
    /// for tests and any external callers. Returns when the proxy should
    /// exit regardless of reason.
    pub async fn wait_for_drain(&self) {
        let _ = self.wait_for_exit().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn force_short_circuits_the_drain_grace() {
        // 60-second drain. Without force, wait_for_exit would sleep that long.
        let coord = Coordinator::new(60);
        coord.trigger_drain();

        // Fire force after ~20ms.
        let coord_clone = coord.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            coord_clone.trigger_force();
        });

        let started = Instant::now();
        let reason = coord.wait_for_exit().await;
        let elapsed = started.elapsed();

        assert_eq!(reason, ExitReason::Forced);
        assert!(
            elapsed < Duration::from_millis(500),
            "force should short-circuit the drain — took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn drain_completes_normally_when_no_force_arrives() {
        let coord = Coordinator::new(0); // 0s grace → DrainComplete immediately
        coord.trigger_drain();
        let reason = coord.wait_for_exit().await;
        assert_eq!(reason, ExitReason::DrainComplete);
    }

    #[tokio::test]
    async fn force_alone_also_exits() {
        // Some callers may want to force-exit without first triggering drain.
        // wait_for_exit() requires drain to start, so this path is "drain
        // then force" — exercise it.
        let coord = Coordinator::new(60);
        let coord_clone = coord.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            coord_clone.trigger_drain();
            tokio::time::sleep(Duration::from_millis(10)).await;
            coord_clone.trigger_force();
        });
        let reason = coord.wait_for_exit().await;
        assert_eq!(reason, ExitReason::Forced);
    }
}
