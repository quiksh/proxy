//! TOML configuration for the registrar sidecar.
//!
//! `${VAR}` / `${VAR:-default}` placeholders are expanded from the environment
//! before parsing (so `instance = "${HOSTNAME}"` works), then `validate()`
//! checks cross-field invariants.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub nats: NatsConfig,
    pub service: ServiceConfig,
    #[serde(default)]
    pub liveness: LivenessConfig,
}

#[derive(Debug, Deserialize)]
pub struct NatsConfig {
    /// `nats://host:4222` or `tls://host:4222` (possibly comma-separated).
    pub url: String,
    /// JetStream KV bucket holding registrations.
    pub bucket: String,
    /// Decentralised-JWT credentials file. Omit for no-auth (trusted network).
    #[serde(default)]
    pub creds_file: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct ServiceConfig {
    pub namespace: String,
    pub service: String,
    /// Unique per replica - typically `${HOSTNAME}`.
    pub instance: String,
    /// The `host:port` quik should route to.
    pub address: String,
    #[serde(default = "default_scheme")]
    pub scheme: String,
    #[serde(default)]
    pub weight: Option<u32>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

fn default_scheme() -> String {
    "http".to_string()
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Http,
    Https,
    Tcp,
}

/// The **liveness** gate: how the registrar decides whether this instance should
/// *stay in the registry at all* - deliberately a different question from quik's
/// own `[upstreams.active_health]` probe, which decides *routing* (readiness).
/// The same split ECS draws between container health and target-group health.
/// The lease is refreshed only while this gate passes, so a dead instance stops
/// heartbeating and its key expires (see `docs/service-registration.md` §6).
/// Point it at a liveness/container endpoint (e.g. `/healthz?source=container`),
/// not the routing endpoint quik probes.
#[derive(Debug, Deserialize)]
pub struct LivenessConfig {
    /// Whether to run the probe at all. Leave `true` (default) for a standalone
    /// registrar (tier 3) - there the probe is the *only* thing that detects
    /// instance death, so it is required. Set `false` in a shared-fate topology
    /// (same Pod/task, or bundled in one container): process death already stops
    /// the heartbeat, so the registrant heartbeats unconditionally and the lease
    /// TTL reaps a dead instance. Left enabled there it is defence-in-depth - it
    /// additionally catches an *alive-but-wedged* instance. Default-on keeps the
    /// fail-safe direction: forgetting to configure it leaves you more protected.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// How to probe the instance: `http` / `https` GET, or a bare `tcp` connect.
    #[serde(default)]
    pub protocol: Protocol,
    /// Path for http(s) probes (ignored for tcp). Prefer a liveness endpoint
    /// distinct from the routing health-check quik runs itself.
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    /// HTTP method for http(s) probes.
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Verify the TLS certificate on `https` probes (default `true`). Set `false`
    /// only for an internal backend with a self-signed cert you trust - it makes
    /// the probe accept any certificate, so an on-path attacker could spoof a
    /// healthy response. Ignored for `http`/`tcp`.
    #[serde(default = "default_tls_verify")]
    pub tls_verify: bool,
    /// Max HTTP redirects the probe will follow (default `0` - none). A liveness
    /// probe should hit the instance directly; following redirects lets a wedged
    /// or hostile instance bounce the probe elsewhere. Raise only if your health
    /// endpoint legitimately redirects.
    #[serde(default = "default_max_redirects")]
    pub max_redirects: usize,
    /// Desired probe + heartbeat cadence. A passing probe also refreshes the
    /// lease (the heartbeat). The effective cadence is capped at one third of the
    /// bucket's TTL (read from NATS at startup) so the key is always re-put well
    /// before it ages out - set this for liveness responsiveness; the cap keeps
    /// it safe regardless.
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    /// Consecutive successes before (re)registering.
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
    /// Consecutive failures before deregistering ("max fails").
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
    /// Initial window (from process start) during which failures never trigger
    /// a deregister - gives the instance time to warm up without flapping.
    #[serde(default = "default_startup_grace_secs")]
    pub startup_grace_secs: u64,
}

impl Default for LivenessConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            protocol: Protocol::default(),
            endpoint: default_endpoint(),
            method: default_method(),
            timeout_ms: default_timeout_ms(),
            tls_verify: default_tls_verify(),
            max_redirects: default_max_redirects(),
            interval_secs: default_interval_secs(),
            healthy_threshold: default_healthy_threshold(),
            unhealthy_threshold: default_unhealthy_threshold(),
            startup_grace_secs: default_startup_grace_secs(),
        }
    }
}

fn default_enabled() -> bool {
    true
}
fn default_endpoint() -> String {
    "/healthz".to_string()
}
fn default_method() -> String {
    "GET".to_string()
}
fn default_timeout_ms() -> u64 {
    2_000
}
fn default_tls_verify() -> bool {
    true
}
fn default_max_redirects() -> usize {
    0
}
fn default_interval_secs() -> u64 {
    5
}
fn default_healthy_threshold() -> u32 {
    1
}
fn default_unhealthy_threshold() -> u32 {
    3
}
fn default_startup_grace_secs() -> u64 {
    30
}

/// The KV key this registration writes: `reg.<namespace>.<service>.<instance>`.
impl ServiceConfig {
    pub fn key(&self) -> String {
        format!("reg.{}.{}.{}", self.namespace, self.service, self.instance)
    }
}

pub fn load(path: &Path) -> Result<Config> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading config {}", path.display()))?;
    let expanded = expand_env(&raw)?;
    let cfg: Config = toml::from_str(&expanded).context("parsing config TOML")?;
    validate(&cfg)?;
    Ok(cfg)
}

fn validate(cfg: &Config) -> Result<()> {
    if cfg.service.address.trim().is_empty() {
        bail!("[service].address is empty");
    }
    if cfg.liveness.healthy_threshold == 0 || cfg.liveness.unhealthy_threshold == 0 {
        bail!("[liveness].healthy_threshold and unhealthy_threshold must be >= 1");
    }
    if cfg.liveness.interval_secs == 0 {
        bail!("[liveness].interval_secs must be >= 1");
    }
    Ok(())
}

/// Expand `${VAR}` and `${VAR:-default}` against the environment. Operates on
/// string slices (not raw bytes) so multi-byte UTF-8 in the config is preserved.
fn expand_env(input: &str) -> Result<String> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}').context("unterminated ${...} in config")?;
        let expr = &after[..end];
        let (name, default) = match expr.split_once(":-") {
            Some((n, d)) => (n, Some(d)),
            None => (expr, None),
        };
        match std::env::var(name) {
            Ok(v) => out.push_str(&v),
            Err(_) => match default {
                Some(d) => out.push_str(d),
                None => bail!("environment variable '{name}' is not set and has no default"),
            },
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_env_preserves_utf8_and_defaults() {
        // SAFETY: single-threaded test; no other thread reads the env here.
        unsafe { std::env::set_var("QR_TEST_VAR", "world") };
        // Non-ASCII outside ${...} must survive byte-for-byte.
        assert_eq!(expand_env("café-${QR_TEST_VAR}").unwrap(), "café-world");
        // Default branch when unset.
        assert_eq!(expand_env("${QR_UNSET:-zürich}").unwrap(), "zürich");
        // Non-ASCII with no placeholders is unchanged.
        assert_eq!(expand_env("naïve-dash").unwrap(), "naïve-dash");
        unsafe { std::env::remove_var("QR_TEST_VAR") };
    }
}
