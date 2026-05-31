//! Serializable response shapes for the admin API.
//!
//! Member responses are intentionally verbose — operators debugging at 3am
//! want to see every contributing factor (lifecycle, passive, active) rather
//! than a single collapsed `state` string. The trade-off is response size,
//! which is fine for a low-volume admin endpoint.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde::{Deserialize, Serialize};

use crate::config::ActiveHealthConfig;
use crate::upstream::{Upstream, UpstreamPoolEntry, unix_now_ms};

#[derive(Serialize)]
pub struct PoolListResponse {
    pub pools: Vec<PoolDetail>,
}

#[derive(Serialize)]
pub struct PoolDetail {
    pub name: String,
    pub balancer: String,
    pub active_health: ActiveHealthSummary,
    pub drain: DrainSummary,
    pub members: Vec<MemberDetail>,
}

#[derive(Serialize)]
pub struct ActiveHealthSummary {
    pub enabled: bool,
    pub path: String,
    pub method: String,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub healthy_threshold: u32,
    pub unhealthy_threshold: u32,
    pub initial_state: String,
}

impl ActiveHealthSummary {
    pub fn from_config(cfg: &ActiveHealthConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            path: cfg.path.clone(),
            method: cfg.method.clone(),
            interval_ms: cfg.interval_ms,
            timeout_ms: cfg.timeout_ms,
            healthy_threshold: cfg.healthy_threshold,
            unhealthy_threshold: cfg.unhealthy_threshold,
            initial_state: format!("{:?}", cfg.initial_state).to_lowercase(),
        }
    }
}

#[derive(Serialize)]
pub struct DrainSummary {
    pub timeout_ms: u64,
}

#[derive(Serialize)]
pub struct MemberDetail {
    /// URL path component identifying this member. Same as `address` today;
    /// kept distinct so a future synthetic-ID scheme can be added without
    /// breaking response consumers.
    pub id: String,
    pub address: String,
    pub scheme: String,
    /// `config` | `runtime`. `config` members were in the config file at boot;
    /// `runtime` members were added via the admin API and will be lost on
    /// restart unless the snapshot is copied back into the config file.
    pub source: String,
    /// `active` | `draining` | `drained`.
    pub lifecycle: String,
    /// Computed AND of all three axes. The single field operators check when
    /// they want to know "is this member taking traffic right now?".
    pub routable: bool,
    pub passive: PassiveDetail,
    pub active: ActiveDetail,
    pub inflight: u32,
}

#[derive(Serialize)]
pub struct PassiveDetail {
    pub ejected: bool,
    pub consecutive_failures: u32,
    pub ejection_count: u32,
}

#[derive(Serialize)]
pub struct ActiveDetail {
    pub enabled: bool,
    pub state: String,
    pub consecutive_ok: u32,
    pub consecutive_fail: u32,
    /// Ms since the last probe completed. `None` if no probe has fired yet
    /// (e.g. probe interval hasn't elapsed since startup, or active health
    /// is disabled).
    pub last_probe_ms_ago: Option<u64>,
}

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub address: String,
    #[serde(default = "default_scheme")]
    pub scheme: String,
    #[serde(default)]
    pub weight: Option<u32>,
    /// Free-form metadata blob, echoed back in GET responses but otherwise
    /// inert. Useful for operators tagging members with deploy-id, region,
    /// etc. for the load-balancing dashboard they build on top.
    #[serde(default)]
    pub metadata: serde_json::Value,
}

fn default_scheme() -> String {
    "http".to_string()
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ErrorResponse {
    pub fn new(msg: &str) -> Self {
        Self {
            error: msg.to_string(),
            detail: None,
        }
    }

    pub fn with_detail(msg: &str, detail: impl Into<String>) -> Self {
        Self {
            error: msg.to_string(),
            detail: Some(detail.into()),
        }
    }
}

// ── Projections from runtime state ─────────────────────────────────────────

pub fn member_to_detail(member: &Upstream, now_ms: u64) -> MemberDetail {
    let lifecycle_state = member.lifecycle.state();
    let inflight = member.health.inflight.load(Ordering::Relaxed);
    let ejected = !member.health.is_eligible(now_ms);
    let last_probe = member.active_health.last_probe_ms();
    let last_probe_ms_ago = if last_probe == 0 {
        None
    } else {
        Some(now_ms.saturating_sub(last_probe))
    };

    MemberDetail {
        id: member.address.clone(),
        address: member.address.clone(),
        scheme: member.scheme.to_string(),
        source: member.source.as_str().to_string(),
        lifecycle: lifecycle_state.as_str().to_string(),
        routable: member.is_routable(now_ms),
        passive: PassiveDetail {
            ejected,
            consecutive_failures: member.health.consecutive_failures.load(Ordering::Relaxed),
            ejection_count: member.health.ejection_count.load(Ordering::Relaxed),
        },
        active: ActiveDetail {
            enabled: member.active_health.enabled,
            state: member.active_health.state().as_str().to_string(),
            consecutive_ok: member.active_health.consecutive_ok(),
            consecutive_fail: member.active_health.consecutive_fail(),
            last_probe_ms_ago,
        },
        inflight,
    }
}

pub fn pool_to_detail(entry: &Arc<UpstreamPoolEntry>) -> PoolDetail {
    let now_ms = unix_now_ms();
    let members = entry.members_snapshot();
    let member_details: Vec<MemberDetail> = members
        .iter()
        .map(|m| member_to_detail(m, now_ms))
        .collect();
    PoolDetail {
        name: entry.name.clone(),
        balancer: format!("{:?}", entry.balancer_name).to_lowercase(),
        active_health: ActiveHealthSummary::from_config(&entry.active_health_cfg),
        drain: DrainSummary {
            timeout_ms: entry.drain_cfg.timeout_ms,
        },
        members: member_details,
    }
}
