//! The registrar loop: run the liveness probe, and register / heartbeat /
//! deregister the instance's NATS KV key accordingly. The probe answers "is
//! this instance alive?" (should it stay in the registry) - not "should traffic
//! route to it?", which is quik's own active-health probe's job.

use std::time::{Duration, Instant};

use bytes::Bytes;

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
/// while still inside the warm-up window (measured from process start) - during
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

/// Derive a safe heartbeat cadence from the configured interval and the bucket's
/// TTL (its max-age, read from NATS at startup). The key must be re-put well
/// before it ages out, so the cadence is capped at one third of the TTL - we may
/// beat *faster* than configured, never slower. A bucket with no TTL
/// (`max_age == 0`) can't expire keys, so the configured interval is used as-is.
/// Pure, so it's unit-tested without NATS.
fn heartbeat_interval(configured: Duration, bucket_ttl: Duration) -> Duration {
    if bucket_ttl.is_zero() {
        return configured; // no lease to outrun
    }
    configured.min(bucket_ttl / 3).max(Duration::from_millis(1))
}

/// The value written at the registration key. Built once and held as `Bytes` so
/// each heartbeat re-publish is a refcount bump, not a re-serialise + deep copy.
fn build_value(svc: &ServiceConfig) -> Result<Bytes> {
    let mut val = serde_json::json!({ "address": svc.address, "scheme": svc.scheme });
    if let Some(w) = svc.weight {
        val["weight"] = serde_json::json!(w);
    }
    if !svc.metadata.is_empty() {
        val["metadata"] = serde_json::to_value(&svc.metadata)?;
    }
    Ok(serde_json::to_vec(&val)?.into())
}

async fn connect(cfg: &Config) -> Result<async_nats::jetstream::kv::Store> {
    let mut opts = async_nats::ConnectOptions::new();
    // SECURITY (auth): credentials come from a file, never inline. Presented to
    // NATS on connect; over a non-tls:// link the JWT is sniffable, so warn.
    if let Some(creds) = &cfg.nats.creds_file {
        if !cfg
            .nats
            .url
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("tls://")
        {
            tracing::warn!(url = %cfg.nats.url, "NATS credentials over a non-TLS URL - the JWT is sent in the clear; use tls://");
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
    // No probe in shared-fate mode: the heartbeat runs unconditionally and
    // deregistration relies on process death + lease TTL (see docs §6).
    let checker = if cfg.liveness.enabled {
        Some(HealthChecker::new(&cfg.liveness, &cfg.service.address)?)
    } else {
        None
    };
    let store = connect(&cfg).await?;

    // The lease is the bucket's TTL (one global max-age - we don't set it per
    // key). Read it and derive a heartbeat capped at TTL/3, so the key is always
    // re-put before it ages out, whatever the configured cadence. Fails safe: a
    // too-slow configured interval is pulled faster, never the reverse.
    let configured = Duration::from_secs(cfg.liveness.interval_secs);
    let mut interval = match store.status().await {
        Ok(s) => {
            let ttl = s.max_age();
            if ttl.is_zero() {
                tracing::warn!(
                    "KV bucket has no TTL (max-age); keys never expire - a dead registrant won't be reaped by lease expiry"
                );
            }
            let i = heartbeat_interval(configured, ttl);
            tracing::info!(
                bucket_ttl_secs = ttl.as_secs(),
                heartbeat_secs = i.as_secs_f64(),
                "derived heartbeat from bucket TTL"
            );
            i
        }
        Err(e) => {
            tracing::warn!(error = %e, configured_secs = configured.as_secs(),
                "could not read bucket TTL; falling back to the configured interval");
            configured
        }
    };

    let started = Instant::now();
    let grace = Duration::from_secs(cfg.liveness.startup_grace_secs);
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut state = ProbeState::default();
    let mut last_ttl_read = Instant::now();

    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;

    tracing::info!(key = %key, address = %cfg.service.address, bucket = %cfg.nats.bucket, liveness = cfg.liveness.enabled, "quik-register started");

    loop {
        tokio::select! {
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
            _ = tick.tick() => {
                let alive = match &checker {
                    Some(c) => c.probe().await,
                    None => true, // shared-fate mode: every tick heartbeats
                };
                let in_grace = started.elapsed() < grace;
                match on_probe(&mut state, alive, in_grace,
                               cfg.liveness.healthy_threshold, cfg.liveness.unhealthy_threshold) {
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
                        tracing::warn!(key = %key, fails = state.consecutive_fail, "liveness probe failing - deregistered");
                    }
                    Action::None if !alive && !state.ever_registered => {
                        if in_grace {
                            tracing::debug!(key = %key, "waiting for instance to come alive (startup grace)");
                        } else {
                            tracing::warn!(key = %key, "instance not alive past startup grace; not registered");
                        }
                    }
                    Action::None => {}
                }
                // Re-derive the cadence periodically so a runtime change to the
                // bucket TTL (e.g. an operator lowering max-age) takes effect
                // without a restart. Cheap: ~one status read per minute.
                if last_ttl_read.elapsed() >= Duration::from_secs(60) {
                    last_ttl_read = Instant::now();
                    if let Ok(s) = store.status().await {
                        let next = heartbeat_interval(configured, s.max_age());
                        if next != interval {
                            tracing::info!(old_secs = interval.as_secs_f64(),
                                heartbeat_secs = next.as_secs_f64(),
                                "bucket TTL changed; re-derived heartbeat");
                            interval = next;
                            tick = tokio::time::interval(interval);
                            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                        }
                    }
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

async fn put(store: &async_nats::jetstream::kv::Store, key: &str, value: &Bytes) {
    if let Err(e) = store.put(key, value.clone()).await {
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
    fn heartbeat_caps_at_third_of_ttl() {
        // Configured slower than TTL/3 → pulled down to TTL/3 (fail safe).
        assert_eq!(
            heartbeat_interval(Duration::from_secs(45), Duration::from_secs(30)),
            Duration::from_secs(10)
        );
        // Configured already faster than TTL/3 → kept as-is.
        assert_eq!(
            heartbeat_interval(Duration::from_secs(5), Duration::from_secs(30)),
            Duration::from_secs(5)
        );
        // Bucket has no TTL → configured used unchanged (nothing to outrun).
        assert_eq!(
            heartbeat_interval(Duration::from_secs(5), Duration::ZERO),
            Duration::from_secs(5)
        );
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
