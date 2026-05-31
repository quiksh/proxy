//! Active health probe task — one per pool with `active_health.enabled`.
//!
//! Tick at the configured interval, snapshot the pool's members, fire a probe
//! at each one whose lifecycle is `active`. Update the per-member
//! [`ActiveHealth`](super::state::ActiveHealth) state from the probe result,
//! emit metrics on the probe and on any state transition.
//!
//! Key constraint: probes do NOT increment the real-traffic counters
//! (`quik_upstream_*` / `quik_requests_total`). They live entirely under the
//! `quik_active_health_check_*` namespace. Operators reading bytes-per-pool
//! should never see probe traffic in those numbers.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Empty};

use crate::config::ActiveHealthConfig;
use crate::shutdown::Coordinator;
use crate::upstream::{Upstream, UpstreamPoolEntry, into_proxy_body, unix_now_ms};

/// Run the probe loop for one pool. Exits when the shutdown coordinator
/// signals drain start. The task takes a snapshot of the member list on
/// each tick — admin-API add/remove takes effect on the next tick.
pub async fn run_pool_probes(pool: Arc<UpstreamPoolEntry>, shutdown: Coordinator) {
    let cfg = pool.active_health_cfg.clone();
    debug_assert!(
        cfg.enabled,
        "run_pool_probes called on a pool with active_health disabled"
    );

    let mut tick = tokio::time::interval(Duration::from_millis(cfg.interval_ms));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let probe_timeout = Duration::from_millis(cfg.timeout_ms);
    let pool_name: Arc<str> = Arc::from(pool.name.as_str());

    tracing::info!(
        pool = %pool_name,
        interval_ms = cfg.interval_ms,
        timeout_ms = cfg.timeout_ms,
        path = %cfg.path,
        "active health probe task started"
    );

    loop {
        tokio::select! {
            _ = shutdown.wait_for_drain_start() => {
                tracing::info!(pool = %pool_name, "active health probe task stopping");
                return;
            }
            _ = tick.tick() => {
                let members = pool.members_snapshot();
                for member in members.iter() {
                    // Skip drained/draining members — operator has taken
                    // them out; probing them is wasted work and would also
                    // pollute the transition metrics.
                    if !member.lifecycle.is_active() {
                        continue;
                    }
                    let pool = Arc::clone(&pool);
                    let member = Arc::clone(member);
                    let cfg = cfg.clone();
                    let pool_name = Arc::clone(&pool_name);
                    tokio::spawn(async move {
                        probe_member(member, pool, cfg, probe_timeout, pool_name).await;
                    });
                }
            }
        }
    }
}

async fn probe_member(
    member: Arc<Upstream>,
    pool: Arc<UpstreamPoolEntry>,
    cfg: ActiveHealthConfig,
    timeout: Duration,
    pool_name: Arc<str>,
) {
    let started = Instant::now();
    let url = format!(
        "{}://{}{}",
        member.scheme.as_str(),
        member.authority.as_str(),
        cfg.path
    );

    let body = into_proxy_body(Empty::<Bytes>::new());
    let req = match Request::builder()
        .method(cfg.method.as_str())
        .uri(&url)
        .header(http::header::HOST, member.authority.as_str())
        .header(http::header::USER_AGENT, "quik/probe")
        .body(body)
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                error = %e, pool = %pool_name, member = %member.name,
                "probe request build failed"
            );
            return;
        }
    };

    let request_future = pool.client.request(req);
    let (outcome, status_for_log) = match tokio::time::timeout(timeout, request_future).await {
        Ok(Ok(resp)) => {
            let status = resp.status().as_u16();
            // Drain body so the connection can be reused by hyper's pool.
            // We don't read more than ~64KB; debug bodies that exceed that
            // get cut off but the probe still completes.
            let _ = resp.into_body().collect().await;
            if cfg.expected_status.matches(status) {
                ("success", Some(status))
            } else {
                ("failure", Some(status))
            }
        }
        Ok(Err(e)) => {
            tracing::debug!(
                pool = %pool_name, member = %member.name, error = %e,
                "probe request error"
            );
            ("failure", None)
        }
        Err(_) => ("timeout", None),
    };

    let elapsed_secs = started.elapsed().as_secs_f64();
    metrics::counter!(
        "quik_active_health_check_total",
        "pool" => pool_name.to_string(),
        "result" => outcome,
    )
    .increment(1);
    metrics::histogram!(
        "quik_active_health_check_duration_seconds",
        "pool" => pool_name.to_string(),
    )
    .record(elapsed_secs);

    let now_ms = unix_now_ms();
    let transition = if outcome == "success" {
        member.active_health.record_success(now_ms)
    } else {
        member.active_health.record_failure(now_ms)
    };

    if let Some((from, to)) = transition {
        metrics::counter!(
            "quik_pool_member_state_transitions_total",
            "pool" => pool_name.to_string(),
            "from" => from.as_str(),
            "to" => to.as_str(),
        )
        .increment(1);
        tracing::info!(
            pool = %pool_name,
            member = %member.name,
            from = from.as_str(),
            to = to.as_str(),
            status = ?status_for_log,
            "active health transition"
        );
    }
}
