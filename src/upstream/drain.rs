//! Drain task - wait for in-flight requests on a member to finish, then
//! either mark the member drained (POST /drain) or remove it from the pool
//! (DELETE /members/{id}).
//!
//! Polling at 200ms rather than a notify pattern: the timeout arm needs a
//! timer anyway, and a polled inflight counter is operationally debuggable
//! from logs/metrics - there's no hidden signal flying around. Cost is one
//! atomic load per active drain per 200ms, negligible.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::upstream::{Upstream, UpstreamPoolEntry};

/// Drive a single member's drain to completion. The member's lifecycle must
/// already be `draining` (the caller - admin DELETE / drain handler -
/// transitions it before spawning this task). When inflight reaches zero or
/// the configured timeout elapses, this:
/// - marks the lifecycle `drained`
/// - if `remove_on_complete`, removes the member from the pool's member list
/// - records drain duration + removed-counter metrics
pub async fn drain_member(
    member: Arc<Upstream>,
    pool: Arc<UpstreamPoolEntry>,
    timeout: Duration,
    remove_on_complete: bool,
) {
    let started = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_millis(200));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let inflight_at_end: u32;
    let timed_out: bool;
    loop {
        tick.tick().await;
        let inflight = member.health.inflight.load(Ordering::Relaxed);
        if inflight == 0 {
            inflight_at_end = 0;
            timed_out = false;
            break;
        }
        if started.elapsed() >= timeout {
            tracing::warn!(
                pool = %pool.name,
                member = %member.name,
                inflight,
                timeout_ms = timeout.as_millis() as u64,
                "drain timeout reached, dropping remaining in-flight"
            );
            inflight_at_end = inflight;
            timed_out = true;
            break;
        }
        // If undrain raced and put the member back to active, abort the
        // drain - no removal, no metrics. Operator-initiated undrain wins.
        if !member.lifecycle.is_draining() {
            tracing::info!(
                pool = %pool.name, member = %member.name,
                "drain task observed lifecycle != draining - aborting"
            );
            return;
        }
    }

    let elapsed_secs = started.elapsed().as_secs_f64();
    metrics::histogram!(
        "quik_pool_member_drain_duration_seconds",
        "pool" => pool.name.clone(),
    )
    .record(elapsed_secs);

    if let Err(state) = member.lifecycle.mark_drained() {
        // Race: undrain happened between the last check and here. Don't
        // mark drained; don't remove.
        tracing::info!(
            pool = %pool.name, member = %member.name,
            state = state.as_str(),
            "drain task observed late lifecycle change - aborting before mark_drained"
        );
        return;
    }

    if remove_on_complete {
        remove_member_from_pool(&pool, &member.address).await;
        let reason = if timed_out {
            "drain_timeout"
        } else {
            "admin_delete"
        };
        metrics::counter!(
            "quik_pool_member_removed_total",
            "pool" => pool.name.clone(),
            "reason" => reason,
        )
        .increment(1);
        tracing::info!(
            pool = %pool.name,
            member = %member.name,
            reason,
            inflight_at_end,
            duration_secs = elapsed_secs,
            "member removed from pool"
        );
    } else {
        tracing::info!(
            pool = %pool.name,
            member = %member.name,
            timed_out,
            inflight_at_end,
            duration_secs = elapsed_secs,
            "member drained (not removed)"
        );
    }
}

/// Atomically swap the pool's member list to one without the named address.
/// Serialised via the pool's `write_lock` so two concurrent removes don't
/// race.
async fn remove_member_from_pool(pool: &UpstreamPoolEntry, address: &str) {
    let _w = pool.write_lock.lock().await;
    let current = pool.members.load_full();
    let next: Vec<Arc<Upstream>> = current
        .iter()
        .filter(|m| m.address != address)
        .cloned()
        .collect();
    pool.members.store(Arc::new(next));
}
