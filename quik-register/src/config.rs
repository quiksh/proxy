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
    pub lease: LeaseConfig,
    #[serde(default)]
    pub health: HealthConfig,
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
    /// Unique per replica — typically `${HOSTNAME}`.
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

#[derive(Debug, Deserialize)]
pub struct LeaseConfig {
    /// Key TTL. Refreshed on every healthy probe, so it must exceed
    /// `health.interval_secs` (validated).
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u64,
}

impl Default for LeaseConfig {
    fn default() -> Self {
        Self {
            ttl_secs: default_ttl_secs(),
        }
    }
}

fn default_ttl_secs() -> u64 {
    30
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Http,
    Https,
    Tcp,
}

#[derive(Debug, Deserialize)]
pub struct HealthConfig {
    /// How to check the service: `http` / `https` GET, or a bare `tcp` connect.
    #[serde(default)]
    pub protocol: Protocol,
    /// Path for http(s) checks (ignored for tcp).
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    /// HTTP method for http(s) checks.
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Probe cadence. A healthy probe also refreshes the lease (the heartbeat),
    /// so this must be shorter than `lease.ttl_secs`.
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    /// Consecutive successes before (re)registering.
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
    /// Consecutive failures before deregistering ("max fails").
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
    /// Initial window (from process start) during which failures never trigger
    /// a deregister — gives the service time to warm up without flapping.
    #[serde(default = "default_startup_grace_secs")]
    pub startup_grace_secs: u64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            protocol: Protocol::default(),
            endpoint: default_endpoint(),
            method: default_method(),
            timeout_ms: default_timeout_ms(),
            interval_secs: default_interval_secs(),
            healthy_threshold: default_healthy_threshold(),
            unhealthy_threshold: default_unhealthy_threshold(),
            startup_grace_secs: default_startup_grace_secs(),
        }
    }
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
    if cfg.health.healthy_threshold == 0 || cfg.health.unhealthy_threshold == 0 {
        bail!("[health].healthy_threshold and unhealthy_threshold must be >= 1");
    }
    if cfg.health.interval_secs == 0 {
        bail!("[health].interval_secs must be >= 1");
    }
    if cfg.health.interval_secs >= cfg.lease.ttl_secs {
        bail!(
            "[health].interval_secs ({}) must be < [lease].ttl_secs ({}) so the lease stays refreshed",
            cfg.health.interval_secs,
            cfg.lease.ttl_secs
        );
    }
    Ok(())
}

/// Expand `${VAR}` and `${VAR:-default}` against the environment.
fn expand_env(input: &str) -> Result<String> {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            let end = input[i + 2..]
                .find('}')
                .map(|e| i + 2 + e)
                .context("unterminated ${...} in config")?;
            let expr = &input[i + 2..end];
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
            i = end + 1;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    Ok(out)
}
