//! Load-balancing algorithms.
//!
//! All three implementations share a key contract: `pick()` increments the
//! chosen member's inflight counter **before returning**. The matching
//! decrement happens via [`super::InflightGuard`] on drop. This eliminates
//! a race where N concurrent picks all see `inflight = 0` and stampede the
//! same member.
//!
//! Random and LeastConnections both scramble a per-pool counter through the
//! 64-bit golden-ratio constant (`SCRAMBLE`) to choose a starting index.
//! The 32-bit cousin `0x9E3779B9` is divisible by 3 - biases 3-member pools
//! to index 0 - so the 64-bit version is non-negotiable here.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::{Upstream, unix_now_ms};

/// 64-bit golden-ratio multiplicative-hash constant (2^64 / φ). Maps a
/// sequential counter onto a scrambled but uniformly-distributed sequence -
/// gives "random-looking" member selection at exactly the cost of
/// round-robin (no PRNG state). The 64-bit constant is coprime to all small
/// pool sizes; its 32-bit cousin 0x9E3779B9 is divisible by 3 which biases
/// 3-member pools to index 0.
const SCRAMBLE: u64 = 0x9E37_79B9_7F4A_7C15;

pub trait Balancer: Send + Sync {
    /// Pick an eligible member and increment its in-flight counter
    /// atomically. Returning + incrementing in the same call eliminates a
    /// race where concurrent picks see a stale `inflight = 0` and stampede
    /// the same member. The caller is responsible for the matching
    /// decrement via `InflightGuard`. Returns `None` if no member passes
    /// the health filter.
    ///
    /// Takes a slice of `Arc<Upstream>` rather than `Upstream` so the proxy
    /// can hand the chosen member off to subsequent code that outlives the
    /// snapshot (the snapshot may be replaced by an admin writer at any
    /// point, but each member Arc remains valid until the last in-flight
    /// request on it drops it).
    fn pick<'a>(&self, upstreams: &'a [Arc<Upstream>]) -> Option<&'a Arc<Upstream>>;
}

#[inline]
fn select(picked: &Arc<Upstream>) {
    picked.health.inflight.fetch_add(1, Ordering::Relaxed);
}

/// Wraparound scan from a per-pool counter position, skipping ejected
/// members. With `n` members and all healthy this picks each one in turn.
#[derive(Default)]
pub struct RoundRobin {
    counter: AtomicUsize,
}

impl RoundRobin {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Balancer for RoundRobin {
    fn pick<'a>(&self, upstreams: &'a [Arc<Upstream>]) -> Option<&'a Arc<Upstream>> {
        let n = upstreams.len();
        if n == 0 {
            return None;
        }
        let now_ms = unix_now_ms();
        let start = self.counter.fetch_add(1, Ordering::Relaxed);
        for i in 0..n {
            let idx = (start + i) % n;
            if upstreams[idx].is_routable(now_ms) {
                select(&upstreams[idx]);
                return Some(&upstreams[idx]);
            }
        }
        None
    }
}

/// Multiplicative-hash variant of round-robin. Same atomic cost, but the
/// scramble means consecutive requests jump around the member list rather
/// than walking sequentially - useful when downstream observers shouldn't
/// see a predictable rotation.
#[derive(Default)]
pub struct Random {
    counter: AtomicU64,
}

impl Random {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Balancer for Random {
    fn pick<'a>(&self, upstreams: &'a [Arc<Upstream>]) -> Option<&'a Arc<Upstream>> {
        let n = upstreams.len();
        if n == 0 {
            return None;
        }
        let now_ms = unix_now_ms();
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        let start = (counter.wrapping_mul(SCRAMBLE) as usize) % n;
        for i in 0..n {
            let idx = (start + i) % n;
            if upstreams[idx].is_routable(now_ms) {
                select(&upstreams[idx]);
                return Some(&upstreams[idx]);
            }
        }
        None
    }
}

/// Pick the eligible member with the lowest current in-flight count.
/// Self-balances against heterogeneous backend response times - slow
/// backends accumulate in-flight and the LB steers around them.
///
/// Tie-breaker uses the same multiplicative-hash trick so a row of zero-load
/// members doesn't pin to `members[0]` at cold start.
#[derive(Default)]
pub struct LeastConnections {
    tie_breaker: AtomicU64,
}

impl LeastConnections {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Balancer for LeastConnections {
    fn pick<'a>(&self, upstreams: &'a [Arc<Upstream>]) -> Option<&'a Arc<Upstream>> {
        let n = upstreams.len();
        if n == 0 {
            return None;
        }
        let now_ms = unix_now_ms();
        let counter = self.tie_breaker.fetch_add(1, Ordering::Relaxed);
        let start = (counter.wrapping_mul(SCRAMBLE) as usize) % n;

        let mut best: Option<&Arc<Upstream>> = None;
        let mut best_load: u32 = u32::MAX;

        for i in 0..n {
            let idx = (start + i) % n;
            let u = &upstreams[idx];
            if !u.is_routable(now_ms) {
                continue;
            }
            let load = u.health.inflight.load(Ordering::Relaxed);
            if load < best_load {
                best = Some(u);
                best_load = load;
            }
        }
        if let Some(u) = best {
            select(u);
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UpstreamHealthConfig;
    use crate::upstream::UpstreamHealth;
    use http::uri::{Authority, Scheme};
    use std::sync::Arc;

    fn make_upstream(name: &str) -> Arc<Upstream> {
        // metrics::counter!/gauge! without an installed recorder fall back to
        // no-op handles, which is exactly right for unit tests.
        use crate::upstream::state::{ActiveHealth, MemberLifecycle};
        Arc::new(Upstream {
            name: name.to_string(),
            address: "127.0.0.1:8080".to_string(),
            authority: Authority::from_static("127.0.0.1:8080"),
            scheme: Scheme::HTTP,
            source: crate::upstream::MemberSource::Config,
            health: Arc::new(UpstreamHealth::new(&UpstreamHealthConfig::default())),
            active_health: Arc::new(ActiveHealth::disabled()),
            lifecycle: Arc::new(MemberLifecycle::new()),
            bytes_sent: metrics::counter!("test"),
            bytes_received: metrics::counter!("test"),
            inflight_gauge: metrics::gauge!("test"),
        })
    }

    #[test]
    fn round_robin_skips_ejected() {
        let members = vec![make_upstream("a"), make_upstream("b"), make_upstream("c")];
        // Eject b far into the future.
        members[1]
            .health
            .ejected_until_ms
            .store(u64::MAX, Ordering::Relaxed);

        let rr = RoundRobin::new();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..30 {
            let pick = rr.pick(&members).unwrap();
            seen.insert(pick.name.clone());
        }
        assert!(seen.contains("a"));
        assert!(seen.contains("c"));
        assert!(!seen.contains("b"), "ejected member must not be picked");
    }

    #[test]
    fn all_ejected_returns_none() {
        let members = vec![make_upstream("a"), make_upstream("b")];
        for m in &members {
            m.health.ejected_until_ms.store(u64::MAX, Ordering::Relaxed);
        }
        assert!(RoundRobin::new().pick(&members).is_none());
        assert!(Random::new().pick(&members).is_none());
        assert!(LeastConnections::new().pick(&members).is_none());
    }

    #[test]
    fn least_connections_picks_min_inflight() {
        let members = vec![make_upstream("a"), make_upstream("b"), make_upstream("c")];
        // Set the gap wide enough that 20 picks (which each increment) on
        // member 'a' don't let it catch up to b/c.
        members[0].health.inflight.store(1, Ordering::Relaxed);
        members[1].health.inflight.store(1000, Ordering::Relaxed);
        members[2].health.inflight.store(500, Ordering::Relaxed);
        let lc = LeastConnections::new();
        for _ in 0..20 {
            assert_eq!(lc.pick(&members).unwrap().name, "a");
        }
    }

    #[test]
    fn least_connections_tie_break_distributes() {
        // All zero - selection should distribute across all members via the
        // multiplicative-hash tie-breaker.
        let members = vec![make_upstream("a"), make_upstream("b"), make_upstream("c")];
        let lc = LeastConnections::new();
        let mut counts = std::collections::HashMap::new();
        for _ in 0..600 {
            let pick = lc.pick(&members).unwrap();
            *counts.entry(pick.name.clone()).or_insert(0) += 1;
        }
        for m in ["a", "b", "c"] {
            assert!(
                counts.get(m).copied().unwrap_or(0) > 0,
                "{m} never selected - tie-breaker not distributing"
            );
        }
    }

    #[test]
    fn ejection_after_threshold_failures() {
        let cfg = UpstreamHealthConfig {
            ejection_threshold: 3,
            ejection_base_ms: 100,
            ejection_max_ms: 1000,
        };
        let h = UpstreamHealth::new(&cfg);
        let now = unix_now_ms();
        // Two failures: still healthy.
        h.record_failure();
        h.record_failure();
        assert!(h.is_eligible(now));
        // Third trips ejection.
        h.record_failure();
        assert!(!h.is_eligible(unix_now_ms()));
    }

    #[test]
    fn success_clears_ejection() {
        let h = UpstreamHealth::new(&UpstreamHealthConfig {
            ejection_threshold: 1,
            ejection_base_ms: 10_000,
            ejection_max_ms: 60_000,
        });
        h.record_failure();
        assert!(!h.is_eligible(unix_now_ms()));
        h.record_success();
        assert!(h.is_eligible(unix_now_ms()));
        assert_eq!(h.consecutive_failures.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn backoff_grows_then_caps() {
        let cfg = UpstreamHealthConfig {
            ejection_threshold: 1,
            ejection_base_ms: 100,
            ejection_max_ms: 1000,
        };
        let h = UpstreamHealth::new(&cfg);
        assert_eq!(h.compute_backoff(0), 100); // 100 << 0 = 100
        assert_eq!(h.compute_backoff(1), 200); // 100 << 1 = 200
        assert_eq!(h.compute_backoff(2), 400);
        assert_eq!(h.compute_backoff(3), 800);
        // capped at ejection_max_ms
        assert_eq!(h.compute_backoff(4), 1000);
        assert_eq!(h.compute_backoff(20), 1000);
    }

    #[test]
    fn pick_increments_inflight() {
        // The Balancer must increment on pick so subsequent picks see the
        // new value (no stampede on burst arrivals).
        let members = vec![make_upstream("a"), make_upstream("b")];
        let rr = RoundRobin::new();
        let _ = rr.pick(&members).unwrap();
        let _ = rr.pick(&members).unwrap();
        assert_eq!(members[0].health.inflight.load(Ordering::Relaxed), 1);
        assert_eq!(members[1].health.inflight.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn inflight_guard_decrements_on_drop() {
        use crate::upstream::InflightGuard;
        let h = Arc::new(UpstreamHealth::new(&UpstreamHealthConfig::default()));
        // Simulate that pick() incremented twice.
        h.inflight.fetch_add(2, Ordering::Relaxed);
        {
            let _g1 = InflightGuard::for_picked(h.clone());
            let _g2 = InflightGuard::for_picked(h.clone());
            assert_eq!(h.inflight.load(Ordering::Relaxed), 2);
        }
        assert_eq!(h.inflight.load(Ordering::Relaxed), 0);
    }
}
