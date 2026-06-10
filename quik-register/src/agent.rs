//! The registrar loop: probe the service, and register / heartbeat / deregister
//! its NATS KV key accordingly.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::signal::unix::{SignalKind, signal};

use crate::config::{Config, ServiceConfig};
use crate::health::HealthChecker;

/// Health-tracking counters driving the register/deregister decision.
#[derive(Default)]
pub struct ProbeState {
    pub consecutive_ok: u32,
    pub consecutive_fail: u32,
    pub registered: bool,
    pub ever_registered: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    None,
    Register,
    Heartbeat,
    Deregister,
}

/// Advance the state machine for one probe result. `in_startup_grace` is true
/// while still inside the warm-up window (measured from process start) — during
/// it, failures never deregister, so a service that's coming up doesn't flap.
/// Pure, so it's unit-tested without NATS or a real service.
pub fn on_probe(
    s: &mut ProbeState,
    healthy: bool,
    in_startup_grace: bool,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
) -> Action {
    if healthy {
        s.consecutive_fail = 0;
        s.consecutive_ok = s.consecutive_ok.saturating_add(1);
        if s.registered {
            return Action::Heartbeat; // re-put refreshes the lease TTL
        }
        if s.consecutive_ok >= healthy_threshold {
            s.registered = true;
            s.ever_registered = true;
            return Action::Register;
        }
        Action::None
    } else {
        s.consecutive_ok = 0;
        s.consecutive_fail = s.consecutive_fail.saturating_add(1);
        if s.registered && !in_startup_grace && s.consecutive_fail >= unhealthy_threshold {
            s.registered = false;
            return Action::Deregister;
        }
        Action::None
    }
}

/// The value written at the registration key.
fn build_value(svc: &ServiceConfig) -> Result<Vec<u8>> {
    let mut val = serde_json::json!({ "address": svc.address, "scheme": svc.scheme });
    if let Some(w) = svc.weight {
        val["weight"] = serde_json::json!(w);
    }
    if !svc.metadata.is_empty() {
        val["metadata"] = serde_json::to_value(&svc.metadata)?;
    }
    Ok(serde_json::to_vec(&val)?)
}

async fn connect(cfg: &Config) -> Result<async_nats::jetstream::kv::Store> {
    let mut opts = async_nats::ConnectOptions::new();
    if let Some(creds) = &cfg.nats.creds_file {
        if !cfg
            .nats
            .url
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("tls://")
        {
            tracing::warn!(url = %cfg.nats.url, "NATS credentials over a non-TLS URL — the JWT is sent in the clear; use tls://");
        }
        opts = opts
            .credentials_file(creds)
            .await
            .with_context(|| format!("reading NATS creds {}", creds.display()))?;
    }
    let client = opts
        .connect(&cfg.nats.url)
        .await
        .with_context(|| format!("connecting to NATS {}", cfg.nats.url))?;
    async_nats::jetstream::new(client)
        .get_key_value(&cfg.nats.bucket)
        .await
        .with_context(|| format!("opening KV bucket {}", cfg.nats.bucket))
}

pub async fn run(cfg: Config) -> Result<()> {
    let key = cfg.service.key();
    let value = build_value(&cfg.service)?;
    let checker = HealthChecker::new(&cfg.health, &cfg.service.address)?;
    let store = connect(&cfg).await?;

    let started = Instant::now();
    let grace = Duration::from_secs(cfg.health.startup_grace_secs);
    let mut tick = tokio::time::interval(Duration::from_secs(cfg.health.interval_secs));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut state = ProbeState::default();

    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;

    tracing::info!(key = %key, address = %cfg.service.address, bucket = %cfg.nats.bucket, "quik-register started");

    loop {
        tokio::select! {
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
            _ = tick.tick() => {
                let healthy = checker.probe().await;
                let in_grace = started.elapsed() < grace;
                match on_probe(&mut state, healthy, in_grace,
                               cfg.health.healthy_threshold, cfg.health.unhealthy_threshold) {
                    Action::Register => {
                        put(&store, &key, &value).await;
                        tracing::info!(key = %key, "registered");
                    }
                    Action::Heartbeat => {
                        put(&store, &key, &value).await;
                        tracing::debug!(key = %key, "heartbeat");
                    }
                    Action::Deregister => {
                        del(&store, &key).await;
                        tracing::warn!(key = %key, fails = state.consecutive_fail, "unhealthy — deregistered");
                    }
                    Action::None if !healthy && !state.ever_registered => {
                        if in_grace {
                            tracing::debug!(key = %key, "waiting for service to become healthy (startup grace)");
                        } else {
                            tracing::warn!(key = %key, "service not healthy past startup grace; not registered");
                        }
                    }
                    Action::None => {}
                }
            }
        }
    }

    // Graceful deregister so quik drains us, rather than waiting for the TTL.
    if state.registered {
        del(&store, &key).await;
        tracing::info!(key = %key, "deregistered on shutdown");
    }
    Ok(())
}

async fn put(store: &async_nats::jetstream::kv::Store, key: &str, value: &[u8]) {
    if let Err(e) = store.put(key, value.to_vec().into()).await {
        tracing::warn!(key = %key, error = %e, "KV put failed (will retry next interval)");
    }
}

async fn del(store: &async_nats::jetstream::kv::Store, key: &str) {
    if let Err(e) = store.delete(key).await {
        tracing::warn!(key = %key, error = %e, "KV delete failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_after_healthy_threshold() {
        let mut s = ProbeState::default();
        assert_eq!(on_probe(&mut s, true, false, 2, 3), Action::None); // 1/2
        assert_eq!(on_probe(&mut s, true, false, 2, 3), Action::Register); // 2/2
        assert!(s.registered);
        // Subsequent healthy probes heartbeat.
        assert_eq!(on_probe(&mut s, true, false, 2, 3), Action::Heartbeat);
    }

    #[test]
    fn deregisters_after_unhealthy_threshold() {
        let mut s = ProbeState {
            registered: true,
            ever_registered: true,
            ..Default::default()
        };
        assert_eq!(on_probe(&mut s, false, false, 1, 3), Action::None); // 1/3
        assert_eq!(on_probe(&mut s, false, false, 1, 3), Action::None); // 2/3
        assert_eq!(on_probe(&mut s, false, false, 1, 3), Action::Deregister); // 3/3
        assert!(!s.registered);
    }

    #[test]
    fn startup_grace_suppresses_deregister() {
        let mut s = ProbeState {
            registered: true,
            ever_registered: true,
            ..Default::default()
        };
        // Even past the threshold, in-grace failures don't deregister.
        for _ in 0..5 {
            assert_eq!(on_probe(&mut s, false, true, 1, 3), Action::None);
        }
        assert!(s.registered);
        // Once out of grace, the next failure (already past threshold) deregisters.
        assert_eq!(on_probe(&mut s, false, false, 1, 3), Action::Deregister);
        assert!(!s.registered);
    }

    #[test]
    fn recovers_and_reregisters() {
        let mut s = ProbeState::default();
        on_probe(&mut s, true, false, 1, 2); // Register
        on_probe(&mut s, false, false, 1, 2);
        assert_eq!(on_probe(&mut s, false, false, 1, 2), Action::Deregister);
        // A healthy probe re-registers (consecutive_ok reset to 1 >= threshold 1).
        assert_eq!(on_probe(&mut s, true, false, 1, 2), Action::Register);
        assert!(s.registered);
    }

    #[test]
    fn healthy_resets_fail_streak() {
        let mut s = ProbeState {
            registered: true,
            ever_registered: true,
            ..Default::default()
        };
        on_probe(&mut s, false, false, 1, 3); // 1 fail
        on_probe(&mut s, true, false, 1, 3); // heartbeat, resets
        assert_eq!(s.consecutive_fail, 0);
        on_probe(&mut s, false, false, 1, 3); // 1 fail again, not deregister
        assert!(s.registered);
    }
}
