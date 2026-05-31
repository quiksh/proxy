//! Per-member orthogonal state axes for lifecycle and active health.
//!
//! Two new pieces of state on each [`super::Upstream`], alongside the
//! existing [`super::UpstreamHealth`] (passive failure tracking):
//!
//! - [`MemberLifecycle`]: operator-controlled. `active → draining → drained`.
//!   Set by admin API calls; never set by failure observation.
//! - [`ActiveHealth`]: probe-controlled. `initial → healthy ↔ unhealthy`.
//!   Set by the per-pool probe task; never set by real traffic.
//!
//! Routing eligibility (computed at pick time by the Balancer) is the AND
//! of all three axes — see [`super::Upstream::is_routable`].

use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

// ── Lifecycle ───────────────────────────────────────────────────────────────

const LIFECYCLE_ACTIVE: u8 = 0;
const LIFECYCLE_DRAINING: u8 = 1;
const LIFECYCLE_DRAINED: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    Active,
    Draining,
    Drained,
}

impl LifecycleState {
    pub fn as_str(self) -> &'static str {
        match self {
            LifecycleState::Active => "active",
            LifecycleState::Draining => "draining",
            LifecycleState::Drained => "drained",
        }
    }

    fn from_raw(raw: u8) -> Self {
        match raw {
            LIFECYCLE_DRAINING => LifecycleState::Draining,
            LIFECYCLE_DRAINED => LifecycleState::Drained,
            _ => LifecycleState::Active,
        }
    }
}

/// Operator-controlled member state. All transitions are forward-only except
/// `draining → active` via undrain. `drained` is terminal.
pub struct MemberLifecycle {
    state: AtomicU8,
    drain_started_ms: AtomicU64,
}

impl MemberLifecycle {
    pub fn new() -> Self {
        Self {
            state: AtomicU8::new(LIFECYCLE_ACTIVE),
            drain_started_ms: AtomicU64::new(0),
        }
    }

    pub fn state(&self) -> LifecycleState {
        LifecycleState::from_raw(self.state.load(Ordering::Relaxed))
    }

    pub fn is_active(&self) -> bool {
        self.state.load(Ordering::Relaxed) == LIFECYCLE_ACTIVE
    }

    pub fn is_draining(&self) -> bool {
        self.state.load(Ordering::Relaxed) == LIFECYCLE_DRAINING
    }

    pub fn is_drained(&self) -> bool {
        self.state.load(Ordering::Relaxed) == LIFECYCLE_DRAINED
    }

    pub fn drain_started_ms(&self) -> u64 {
        self.drain_started_ms.load(Ordering::Relaxed)
    }

    /// Transition `active → draining`. Idempotent on the second call: returns
    /// `Ok(())` if already draining. Errors if the member has already drained.
    pub fn begin_drain(&self, now_ms: u64) -> Result<(), LifecycleState> {
        match self.state.compare_exchange(
            LIFECYCLE_ACTIVE,
            LIFECYCLE_DRAINING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                self.drain_started_ms.store(now_ms, Ordering::Relaxed);
                Ok(())
            }
            Err(curr) if curr == LIFECYCLE_DRAINING => Ok(()),
            Err(curr) => Err(LifecycleState::from_raw(curr)),
        }
    }

    /// Transition `draining → drained`. Terminal — no further state changes
    /// allowed. Errors if not currently draining.
    pub fn mark_drained(&self) -> Result<(), LifecycleState> {
        match self.state.compare_exchange(
            LIFECYCLE_DRAINING,
            LIFECYCLE_DRAINED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(()),
            Err(curr) => Err(LifecycleState::from_raw(curr)),
        }
    }

    /// Transition `draining → active`. Errors if drained or already active.
    /// 410 Gone-style: a drained member must be re-added, not undrained.
    pub fn undrain(&self) -> Result<(), LifecycleState> {
        match self.state.compare_exchange(
            LIFECYCLE_DRAINING,
            LIFECYCLE_ACTIVE,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                self.drain_started_ms.store(0, Ordering::Relaxed);
                Ok(())
            }
            Err(curr) => Err(LifecycleState::from_raw(curr)),
        }
    }
}

impl Default for MemberLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

// ── Active health ──────────────────────────────────────────────────────────

const AH_INITIAL: u8 = 0;
const AH_HEALTHY: u8 = 1;
const AH_UNHEALTHY: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveHealthState {
    Initial,
    Healthy,
    Unhealthy,
}

impl ActiveHealthState {
    pub fn as_str(self) -> &'static str {
        match self {
            ActiveHealthState::Initial => "initial",
            ActiveHealthState::Healthy => "healthy",
            ActiveHealthState::Unhealthy => "unhealthy",
        }
    }

    fn from_raw(raw: u8) -> Self {
        match raw {
            AH_HEALTHY => ActiveHealthState::Healthy,
            AH_UNHEALTHY => ActiveHealthState::Unhealthy,
            _ => ActiveHealthState::Initial,
        }
    }

    fn to_raw(self) -> u8 {
        match self {
            ActiveHealthState::Initial => AH_INITIAL,
            ActiveHealthState::Healthy => AH_HEALTHY,
            ActiveHealthState::Unhealthy => AH_UNHEALTHY,
        }
    }
}

/// Active health state for one member. When `enabled = false`, the member is
/// always eligible — used for pools that haven't opted into active checks so
/// existing behaviour is unchanged.
pub struct ActiveHealth {
    pub enabled: bool,
    pub healthy_threshold: u32,
    pub unhealthy_threshold: u32,
    state: AtomicU8,
    consecutive_ok: AtomicU32,
    consecutive_fail: AtomicU32,
    last_probe_ms: AtomicU64,
}

impl ActiveHealth {
    /// Construct an always-eligible disabled instance. Used for pools without
    /// active checks configured — `is_eligible` returns true unconditionally.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            healthy_threshold: 1,
            unhealthy_threshold: 1,
            state: AtomicU8::new(AH_HEALTHY),
            consecutive_ok: AtomicU32::new(0),
            consecutive_fail: AtomicU32::new(0),
            last_probe_ms: AtomicU64::new(0),
        }
    }

    /// Construct an enabled instance with a chosen initial state. Pessimistic
    /// (`Unhealthy`) means the member doesn't take traffic until probes
    /// succeed enough to flip it; optimistic (`Healthy`) means it takes
    /// traffic immediately and only stops if probes fail enough.
    pub fn new(
        healthy_threshold: u32,
        unhealthy_threshold: u32,
        initial: ActiveHealthState,
    ) -> Self {
        Self {
            enabled: true,
            healthy_threshold,
            unhealthy_threshold,
            state: AtomicU8::new(initial.to_raw()),
            consecutive_ok: AtomicU32::new(0),
            consecutive_fail: AtomicU32::new(0),
            last_probe_ms: AtomicU64::new(0),
        }
    }

    pub fn state(&self) -> ActiveHealthState {
        ActiveHealthState::from_raw(self.state.load(Ordering::Relaxed))
    }

    pub fn consecutive_ok(&self) -> u32 {
        self.consecutive_ok.load(Ordering::Relaxed)
    }

    pub fn consecutive_fail(&self) -> u32 {
        self.consecutive_fail.load(Ordering::Relaxed)
    }

    pub fn last_probe_ms(&self) -> u64 {
        self.last_probe_ms.load(Ordering::Relaxed)
    }

    /// Eligible iff disabled, or enabled and currently `Healthy`. `Initial`
    /// counts as ineligible when `enabled` (pessimistic by construction) —
    /// callers that want optimistic startup pass `initial = Healthy`.
    pub fn is_eligible(&self) -> bool {
        if !self.enabled {
            return true;
        }
        self.state.load(Ordering::Relaxed) == AH_HEALTHY
    }

    /// Record a probe success. Returns `Some((from, to))` if this call caused
    /// a state flip — callers fire transition metrics on that.
    pub fn record_success(&self, now_ms: u64) -> Option<(ActiveHealthState, ActiveHealthState)> {
        if !self.enabled {
            return None;
        }
        self.last_probe_ms.store(now_ms, Ordering::Relaxed);
        self.consecutive_fail.store(0, Ordering::Relaxed);
        let ok = self.consecutive_ok.fetch_add(1, Ordering::Relaxed) + 1;
        let curr_raw = self.state.load(Ordering::Relaxed);
        let curr = ActiveHealthState::from_raw(curr_raw);
        if curr == ActiveHealthState::Healthy {
            return None;
        }
        if ok >= self.healthy_threshold {
            self.state.store(AH_HEALTHY, Ordering::Relaxed);
            return Some((curr, ActiveHealthState::Healthy));
        }
        None
    }

    /// Record a probe failure (any kind — wrong status, timeout, connect
    /// error). Returns `Some((from, to))` if this call caused a flip.
    pub fn record_failure(&self, now_ms: u64) -> Option<(ActiveHealthState, ActiveHealthState)> {
        if !self.enabled {
            return None;
        }
        self.last_probe_ms.store(now_ms, Ordering::Relaxed);
        self.consecutive_ok.store(0, Ordering::Relaxed);
        let fail = self.consecutive_fail.fetch_add(1, Ordering::Relaxed) + 1;
        let curr_raw = self.state.load(Ordering::Relaxed);
        let curr = ActiveHealthState::from_raw(curr_raw);
        if curr == ActiveHealthState::Unhealthy {
            return None;
        }
        if fail >= self.unhealthy_threshold {
            self.state.store(AH_UNHEALTHY, Ordering::Relaxed);
            return Some((curr, ActiveHealthState::Unhealthy));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── MemberLifecycle ────────────────────────────────────────────────────

    #[test]
    fn lifecycle_starts_active() {
        let l = MemberLifecycle::new();
        assert!(l.is_active());
        assert_eq!(l.state(), LifecycleState::Active);
    }

    #[test]
    fn begin_drain_is_idempotent() {
        let l = MemberLifecycle::new();
        assert!(l.begin_drain(1000).is_ok());
        assert!(l.is_draining());
        assert_eq!(l.drain_started_ms(), 1000);
        // Calling again on the same draining state must succeed but not
        // overwrite the timestamp — operators want to know when drain *began*.
        assert!(l.begin_drain(2000).is_ok());
        assert_eq!(l.drain_started_ms(), 1000);
    }

    #[test]
    fn drained_is_terminal() {
        let l = MemberLifecycle::new();
        l.begin_drain(1000).unwrap();
        l.mark_drained().unwrap();
        assert!(l.is_drained());
        // No transition back is possible — undrain must error.
        let err = l.undrain().unwrap_err();
        assert_eq!(err, LifecycleState::Drained);
        // Begin_drain on a drained member is also an error.
        let err = l.begin_drain(3000).unwrap_err();
        assert_eq!(err, LifecycleState::Drained);
    }

    #[test]
    fn undrain_returns_to_active() {
        let l = MemberLifecycle::new();
        l.begin_drain(1000).unwrap();
        l.undrain().unwrap();
        assert!(l.is_active());
        assert_eq!(l.drain_started_ms(), 0);
    }

    #[test]
    fn cannot_undrain_active_member() {
        let l = MemberLifecycle::new();
        let err = l.undrain().unwrap_err();
        assert_eq!(err, LifecycleState::Active);
    }

    #[test]
    fn cannot_mark_drained_from_active() {
        let l = MemberLifecycle::new();
        let err = l.mark_drained().unwrap_err();
        assert_eq!(err, LifecycleState::Active);
    }

    // ── ActiveHealth ───────────────────────────────────────────────────────

    #[test]
    fn disabled_is_always_eligible() {
        let h = ActiveHealth::disabled();
        assert!(h.is_eligible());
        // Recording success/failure is a no-op for disabled instances.
        assert!(h.record_success(1).is_none());
        assert!(h.record_failure(1).is_none());
        assert!(h.is_eligible());
    }

    #[test]
    fn pessimistic_starts_ineligible() {
        let h = ActiveHealth::new(2, 3, ActiveHealthState::Unhealthy);
        assert!(!h.is_eligible());
        assert_eq!(h.state(), ActiveHealthState::Unhealthy);
    }

    #[test]
    fn optimistic_starts_eligible() {
        let h = ActiveHealth::new(2, 3, ActiveHealthState::Healthy);
        assert!(h.is_eligible());
    }

    #[test]
    fn flips_to_healthy_after_threshold_successes() {
        let h = ActiveHealth::new(2, 3, ActiveHealthState::Unhealthy);
        assert!(h.record_success(1).is_none()); // 1/2 ok
        assert!(!h.is_eligible());
        let t = h.record_success(2).unwrap(); // 2/2 ok → healthy
        assert_eq!(
            t,
            (ActiveHealthState::Unhealthy, ActiveHealthState::Healthy)
        );
        assert!(h.is_eligible());
    }

    #[test]
    fn flips_to_unhealthy_after_threshold_failures() {
        let h = ActiveHealth::new(2, 3, ActiveHealthState::Healthy);
        assert!(h.record_failure(1).is_none()); // 1/3
        assert!(h.record_failure(2).is_none()); // 2/3
        assert!(h.is_eligible()); // still healthy
        let t = h.record_failure(3).unwrap(); // 3/3 → unhealthy
        assert_eq!(
            t,
            (ActiveHealthState::Healthy, ActiveHealthState::Unhealthy)
        );
        assert!(!h.is_eligible());
    }

    #[test]
    fn success_resets_failure_streak() {
        let h = ActiveHealth::new(2, 3, ActiveHealthState::Healthy);
        h.record_failure(1);
        h.record_failure(2);
        h.record_success(3);
        // Counter reset — needs three more failures to flip, not one.
        h.record_failure(4);
        h.record_failure(5);
        assert!(h.is_eligible());
        h.record_failure(6);
        assert!(!h.is_eligible());
    }

    #[test]
    fn no_repeat_transition_when_already_in_target() {
        let h = ActiveHealth::new(1, 1, ActiveHealthState::Healthy);
        assert!(h.record_success(1).is_none()); // already healthy → no fire
        let t = h.record_failure(2).unwrap();
        assert_eq!(t.1, ActiveHealthState::Unhealthy);
        assert!(h.record_failure(3).is_none()); // already unhealthy
    }
}
