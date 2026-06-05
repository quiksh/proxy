//! Shutdown coordination with a phased signal protocol.
//!
//! On the first SIGTERM/SIGINT the proxy runs three phases:
//!
//! 1. **pre-drain (edge-withdraw):** `/healthz` flips to 503 immediately but
//!    the listeners keep accepting for `pre_drain_grace_seconds`. This lets a
//!    perimeter (e.g. Cloudflare) notice the 503 via its own health check and
//!    stop routing *before* we stop accepting — so in-flight requests aren't
//!    cut. With `pre_drain_grace_seconds = 0` (the default) this phase is
//!    instantaneous and behaviour matches a proxy with no edge in front.
//! 2. **drain:** listeners stop accepting; in-flight requests get up to
//!    `drain_grace_seconds` to finish.
//! 3. **exit.**
//!
//! A second signal at any point triggers *force-exit*: it short-circuits the
//! pre-drain grace **and** the drain grace, aborts pending connections, and the
//! process exits immediately. A third signal is left to the OS default.
//!
//! Internally this is three `tokio::sync::watch` channels so every spawned task
//! can `select!` on the relevant phase without polling: `health_drain` (drives
//! `/healthz`), `drain` (drives listener stop-accept), and `force`.

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
    /// Pre-drain (edge-withdraw) phase: `/healthz` returns 503 but listeners
    /// keep accepting. Set at the start of phase 1.
    health_drain_tx: Arc<watch::Sender<bool>>,
    health_drain_rx: watch::Receiver<bool>,
    drain_tx: Arc<watch::Sender<bool>>,
    drain_rx: watch::Receiver<bool>,
    force_tx: Arc<watch::Sender<bool>>,
    force_rx: watch::Receiver<bool>,
    drain_grace: Duration,
    pre_drain_grace: Duration,
}

impl Coordinator {
    pub fn new(drain_grace_seconds: u64, pre_drain_grace_seconds: u64) -> Self {
        let (health_drain_tx, health_drain_rx) = watch::channel(false);
        let (drain_tx, drain_rx) = watch::channel(false);
        let (force_tx, force_rx) = watch::channel(false);
        Self {
            health_drain_tx: Arc::new(health_drain_tx),
            health_drain_rx,
            drain_tx: Arc::new(drain_tx),
            drain_rx,
            force_tx: Arc::new(force_tx),
            force_rx,
            drain_grace: Duration::from_secs(drain_grace_seconds),
            pre_drain_grace: Duration::from_secs(pre_drain_grace_seconds),
        }
    }

    /// True once the proxy has begun shutting down — covers both the pre-drain
    /// (edge-withdraw) phase and the drain phase. Drives `/healthz` → 503.
    pub fn is_health_draining(&self) -> bool {
        *self.health_drain_rx.borrow()
    }

    /// True once listeners should stop accepting (drain phase). This is *after*
    /// the pre-drain grace, so it lags `is_health_draining` by up to
    /// `pre_drain_grace`.
    pub fn is_draining(&self) -> bool {
        *self.drain_rx.borrow()
    }

    pub fn is_forcing(&self) -> bool {
        *self.force_rx.borrow()
    }

    pub fn drain_grace(&self) -> Duration {
        self.drain_grace
    }

    pub fn pre_drain_grace(&self) -> Duration {
        self.pre_drain_grace
    }

    /// Begin the pre-drain (edge-withdraw) phase: `/healthz` → 503 while
    /// listeners keep accepting. Idempotent.
    pub fn begin_pre_drain(&self) {
        let _ = self.health_drain_tx.send(true);
    }

    /// Trigger the drain phase (listeners stop accepting). Also marks
    /// health-draining so `/healthz` reflects shutdown even if drain is
    /// triggered directly (e.g. by a test) without a pre-drain phase.
    pub fn trigger_drain(&self) {
        let _ = self.health_drain_tx.send(true);
        let _ = self.drain_tx.send(true);
    }

    /// Trigger an immediate force-exit. Aborts the rest of the pre-drain and
    /// drain grace periods and causes per-connection tasks to drop their
    /// connections instead of waiting.
    pub fn trigger_force(&self) {
        let _ = self.force_tx.send(true);
    }

    /// Run the phased shutdown: pre-drain (edge-withdraw) → wait
    /// `pre_drain_grace` (or until force) → drain. Shared by the signal handler
    /// and by tests. Does not itself trigger force — the caller (second signal)
    /// does that, and this observes it to cut the pre-drain wait short.
    pub async fn run_shutdown_sequence(&self) {
        self.begin_pre_drain();
        // Hold at 503-but-accepting for the grace window so the edge withdraws,
        // unless an operator double-taps to force exit.
        tokio::select! {
            _ = tokio::time::sleep(self.pre_drain_grace) => {}
            _ = self.wait_for_force() => {}
        }
        self.trigger_drain();
    }

    pub fn install_signal_handlers(&self) {
        let coord = self.clone();
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

            // First signal: begin the phased shutdown (pre-drain → drain).
            tokio::select! {
                _ = sigterm.recv() => tracing::info!("received SIGTERM, beginning shutdown (send again to force-exit)"),
                _ = sigint.recv()  => tracing::info!("received SIGINT, beginning shutdown (send again to force-exit)"),
            }
            let seq = coord.clone();
            tokio::spawn(async move { seq.run_shutdown_sequence().await });

            // Second signal: force exit. Short-circuits the pre-drain grace and
            // the drain grace alike. A *third* signal is the OS default.
            tokio::select! {
                _ = sigterm.recv() => tracing::warn!(
                    "received SIGTERM again — forcing immediate shutdown, in-flight requests will be aborted"
                ),
                _ = sigint.recv()  => tracing::warn!(
                    "received SIGINT again — forcing immediate shutdown, in-flight requests will be aborted"
                ),
            }
            coord.trigger_force();
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
        let coord = Coordinator::new(60, 0);
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
        let coord = Coordinator::new(0, 0); // 0s grace → DrainComplete immediately
        coord.trigger_drain();
        let reason = coord.wait_for_exit().await;
        assert_eq!(reason, ExitReason::DrainComplete);
    }

    #[tokio::test]
    async fn force_alone_also_exits() {
        // Some callers may want to force-exit without first triggering drain.
        // wait_for_exit() requires drain to start, so this path is "drain
        // then force" — exercise it.
        let coord = Coordinator::new(60, 0);
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

    // ── Pre-drain (edge-withdraw) phase sequencer ───────────────────────────

    #[tokio::test(start_paused = true)]
    async fn pre_drain_precedes_drain() {
        // 5s edge-withdraw grace: /healthz must flip immediately, but the
        // listeners (which select on is_draining) must keep accepting until
        // the grace elapses.
        let coord = Coordinator::new(60, 5);
        let c = coord.clone();
        let h = tokio::spawn(async move { c.run_shutdown_sequence().await });

        // Let the sequence run up to the pre-drain sleep.
        tokio::task::yield_now().await;
        assert!(
            coord.is_health_draining(),
            "/healthz should report draining at once"
        );
        assert!(
            !coord.is_draining(),
            "listeners must keep accepting during the edge-withdraw grace"
        );

        // Awaiting the task lets paused time auto-advance past the grace.
        h.await.unwrap();
        assert!(coord.is_draining(), "drain begins only after the grace");
    }

    #[tokio::test(start_paused = true)]
    async fn force_during_pre_drain_cuts_the_grace() {
        // A huge grace that we never actually wait out — force must cut it.
        let coord = Coordinator::new(60, 3600);
        let c = coord.clone();
        let h = tokio::spawn(async move { c.run_shutdown_sequence().await });

        tokio::task::yield_now().await;
        assert!(coord.is_health_draining());
        assert!(!coord.is_draining());

        coord.trigger_force();
        h.await.unwrap();
        assert!(
            coord.is_draining(),
            "force short-circuits the pre-drain grace and begins drain"
        );
        assert_eq!(coord.wait_for_exit().await, ExitReason::Forced);
    }

    #[tokio::test]
    async fn zero_pre_drain_collapses_to_immediate_drain() {
        // Default config (pre_drain_grace_seconds = 0): pre-drain and drain
        // coincide, matching behaviour without an edge-withdraw grace.
        let coord = Coordinator::new(0, 0);
        coord.run_shutdown_sequence().await;
        assert!(coord.is_health_draining());
        assert!(coord.is_draining());
    }
}
