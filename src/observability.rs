//! Tracing + metrics initialisation, plus a periodic sampler for in-flight
//! gauges.
//!
//! Tracing supports two output formats: `json` (one object per line,
//! machine-parseable, the default) and `key_value` (compact `field=value`
//! prefixed with timestamp/level/target). Per-request fields like
//! `request_id`, `method`, `path`, `peer` flow through `tracing::Span` and
//! attach automatically to every event emitted within the request.
//!
//! Metric histogram buckets are tuned for proxy hop targets (p50 < 200µs,
//! p99 < 1ms) - coarser buckets miss interesting latency, finer ones bloat
//! the cardinality budget.
//!
//! [`inflight_sampler`] copies each upstream's atomic inflight counter into
//! its pre-built Prometheus gauge handle on a tick (default 5s). Sampling
//! rather than emitting per-request keeps the hot path allocation-free for
//! the gauge label set.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

use crate::config::{LogFormat, LoggingConfig};
use crate::shutdown::Coordinator;
use crate::upstream::{Pool, unix_now_ms};

pub fn init_tracing(cfg: &LoggingConfig) -> Result<()> {
    let env_filter = EnvFilter::try_new(&cfg.level)
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let registry = tracing_subscriber::registry().with(env_filter);

    let init_err = |e: tracing_subscriber::util::TryInitError| anyhow::anyhow!("tracing init: {e}");

    match cfg.format {
        LogFormat::Json => {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(false)
                .flatten_event(true);
            registry.with(fmt_layer).try_init().map_err(init_err)?;
        }
        LogFormat::KeyValue => {
            // tracing-subscriber's compact formatter renders structured fields
            // as `field=value` pairs after a timestamp + level + target prefix.
            let fmt_layer = tracing_subscriber::fmt::layer()
                .compact()
                .with_target(true)
                .with_thread_ids(false)
                .with_thread_names(false);
            registry.with(fmt_layer).try_init().map_err(init_err)?;
        }
    }

    Ok(())
}

pub fn init_metrics() -> Result<PrometheusHandle> {
    // Buckets tuned for sub-millisecond proxy hop targets (p50<200µs, p99<1ms).
    let buckets: &[f64] = &[
        0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5,
        1.0, 2.5, 5.0,
    ];
    let tls_buckets: &[f64] = &[
        0.0005, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
    ];

    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full("quik_request_duration_seconds".to_string()),
            buckets,
        )
        .context("setting request duration buckets")?
        .set_buckets_for_metric(
            Matcher::Full("quik_tls_handshake_seconds".to_string()),
            tls_buckets,
        )
        .context("setting tls handshake buckets")?
        .install_recorder()
        .context("installing prometheus recorder")?;

    metrics::describe_counter!(
        "quik_requests_total",
        "Total requests handled, labelled by route and status"
    );
    metrics::describe_histogram!(
        "quik_request_duration_seconds",
        "End-to-end request duration in seconds, labelled by route"
    );
    metrics::describe_counter!(
        "quik_upstream_selected_total",
        "Upstream selections, labelled by pool and member"
    );
    metrics::describe_counter!("quik_proxy_errors_total", "Proxy errors, labelled by kind");
    metrics::describe_gauge!("quik_inbound_connections", "Current inbound connections");
    metrics::describe_counter!(
        "quik_tls_handshakes_total",
        "TLS handshakes, labelled by outcome"
    );
    metrics::describe_histogram!(
        "quik_tls_handshake_seconds",
        "TLS handshake duration in seconds"
    );
    metrics::describe_counter!(
        "quik_auth_total",
        "Auth outcomes per [[auth]] block: ok / missing_token / bad_signature / bad_claims / spoofed_header / …"
    );
    metrics::describe_counter!(
        "quik_jwks_fetches_total",
        "JWKS refreshes per [[auth]] block. Steady-state value should be small; spikes indicate kid churn or cache thrashing."
    );
    metrics::describe_histogram!(
        "quik_jwks_fetch_duration_seconds",
        "Wall-clock time spent fetching a JWKS document, per [[auth]] block"
    );
    metrics::describe_counter!(
        "quik_upstream_ejections_total",
        "Number of times each upstream member has been ejected by passive health (cumulative; rate over time = ejection frequency)"
    );
    metrics::describe_counter!(
        "quik_upstream_bytes_sent_total",
        "Bytes the proxy has sent to each upstream member (request bodies)"
    );
    metrics::describe_counter!(
        "quik_upstream_bytes_received_total",
        "Bytes the proxy has received from each upstream member (response bodies)"
    );
    metrics::describe_gauge!(
        "quik_upstream_inflight",
        "Current in-flight requests per upstream member (sampled - gauge is updated periodically, not per-request)"
    );

    // Live registration + active health
    metrics::describe_gauge!(
        "quik_pool_members_total",
        "Members per pool by state. Buckets are mutually exclusive with precedence draining > unhealthy_passive > unhealthy_active > healthy"
    );
    metrics::describe_counter!(
        "quik_pool_member_added_total",
        "Members added via the admin API (cumulative)"
    );
    metrics::describe_counter!(
        "quik_pool_member_removed_total",
        "Members removed from a pool; reason label distinguishes admin_delete from drain_timeout"
    );
    metrics::describe_histogram!(
        "quik_pool_member_drain_duration_seconds",
        "Wall-clock from drain start to either inflight=0 or drain timeout"
    );
    metrics::describe_counter!(
        "quik_pool_member_state_transitions_total",
        "State transitions per member; from/to labels are one of healthy|unhealthy|initial|active|draining|drained"
    );
    metrics::describe_counter!(
        "quik_active_health_check_total",
        "Active health probe outcomes per pool. Result is success|failure|timeout. Disjoint from real-traffic counters."
    );
    metrics::describe_histogram!(
        "quik_active_health_check_duration_seconds",
        "Wall-clock per active health probe"
    );

    // NATS service registration (feature `nats`).
    metrics::describe_gauge!(
        "quik_nats_connected",
        "NATS connection state (1 connected, 0 disconnected). 0 means membership is frozen at last-known."
    );
    metrics::describe_counter!(
        "quik_nats_reconcile_total",
        "NATS reconcile actions applied to pool membership, by action (add|remove)"
    );
    metrics::describe_counter!(
        "quik_nats_watch_events_total",
        "KV watch events received, by op (put|delete|purge)"
    );
    metrics::describe_counter!(
        "quik_nats_registration_rejected_total",
        "Registrations refused by reason: address_not_allowed | pool_member_cap | service_quota"
    );

    Ok(handle)
}

/// Periodically copy each upstream member's `inflight` counter into a
/// Prometheus gauge. Sampling (rather than per-request emission) keeps the
/// hot path allocation-free for the metric labels - the pre-built gauge
/// handle on each `Upstream` is just an `Arc` clone.
///
/// Runs until drain is triggered, then returns so the runtime can finish.
pub async fn inflight_sampler(pool: Arc<Pool>, interval: Duration, shutdown: Coordinator) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.wait_for_drain_start() => return,
            _ = tick.tick() => {
                let snap = pool.snapshot();
                let now_ms = unix_now_ms();
                for entry in snap.values() {
                    let members = entry.members_snapshot();
                    let (mut healthy, mut draining, mut un_passive, mut un_active) =
                        (0u64, 0u64, 0u64, 0u64);
                    for member in members.iter() {
                        let n = member.health.inflight.load(Ordering::Relaxed);
                        member.inflight_gauge.set(n as f64);

                        // Bucket per design: draining > passive > active > healthy.
                        // Each member contributes to exactly one bucket so the
                        // four label values sum to the pool's member count.
                        let bucket = if member.lifecycle.is_draining() {
                            &mut draining
                        } else if !member.health.is_eligible(now_ms) {
                            &mut un_passive
                        } else if !member.active_health.is_eligible() {
                            &mut un_active
                        } else {
                            &mut healthy
                        };
                        *bucket += 1;
                    }
                    let pool_label = entry.name.clone();
                    metrics::gauge!(
                        "quik_pool_members_total",
                        "pool" => pool_label.clone(), "state" => "healthy"
                    )
                    .set(healthy as f64);
                    metrics::gauge!(
                        "quik_pool_members_total",
                        "pool" => pool_label.clone(), "state" => "draining"
                    )
                    .set(draining as f64);
                    metrics::gauge!(
                        "quik_pool_members_total",
                        "pool" => pool_label.clone(), "state" => "unhealthy_passive"
                    )
                    .set(un_passive as f64);
                    metrics::gauge!(
                        "quik_pool_members_total",
                        "pool" => pool_label, "state" => "unhealthy_active"
                    )
                    .set(un_active as f64);
                }
            }
        }
    }
}
