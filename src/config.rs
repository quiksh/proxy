//! TOML configuration schema + loading.
//!
//! Loading is two-step: read the file, then expand `${VAR}` / `${VAR:-default}`
//! placeholders against the environment *before* TOML parsing. This lets
//! secrets live in env vars while keeping the rest of the config in version
//! control. `validate()` runs after parse to catch references to undefined
//! upstreams / auth blocks and other cross-field invariants.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub mode: Mode,
    pub listener: ListenerConfig,
    pub admin: AdminConfig,
    #[serde(default)]
    pub shutdown: ShutdownConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub upstreams: Vec<UpstreamPoolConfig>,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    /// Named JWT auth configurations. Routes opt in via `auth = "name"`.
    #[serde(default)]
    pub auth: Vec<AuthBlockConfig>,
    /// Optional egress (forward) proxy listener. When present, quik runs a
    /// CONNECT proxy on the given bind address with the configured allow/deny
    /// rules. Absent → no egress listener.
    #[serde(default)]
    pub egress: Option<EgressConfig>,
    /// Optional NATS-backed service registration. Only *acted upon* in a
    /// `--features nats` build; parsed unconditionally so a config is portable
    /// and a feature/config mismatch fails fast (see `validate`).
    #[serde(default)]
    pub nats: Option<NatsConfig>,
}

/// Connection settings for the NATS service-registration watcher.
/// See `docs/service-registration.md`.
#[derive(Debug, Clone, Deserialize)]
pub struct NatsConfig {
    /// NATS server URL, e.g. `nats://host:4222` or `tls://host:4222`.
    pub url: String,
    /// JetStream KV bucket holding registrations.
    pub bucket: String,
    /// Path to a NATS credentials file (decentralised JWT). Omit for no-auth
    /// (local demo) or when credentials are supplied another way.
    #[serde(default)]
    pub creds_file: Option<PathBuf>,
    /// Seconds between reconnect attempts while the connection is down.
    #[serde(default = "default_nats_reconnect_secs")]
    pub reconnect_secs: u64,
}

fn default_nats_reconnect_secs() -> u64 {
    5
}

/// Per-pool NATS registration binding. A pool carrying this block is populated
/// from the KV subtree `subject`; backends self-register there. The hardening
/// controls live here: the registrable-address allow-list (H1) and the member
/// caps (H2).
#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamNatsConfig {
    /// KV key subject filter feeding this pool, e.g. `reg.shop.checkout.>`.
    pub subject: String,
    /// Registrable-address allow-list (H1): CIDR (`10.0.0.0/8`) or host-suffix
    /// (`.svc.cluster.local`) entries. A self-asserted address outside this set
    /// is rejected. Required (and non-empty) - a pool admitting self-registered
    /// members must state where they may live; this fails *safe*.
    #[serde(default)]
    pub allow_addresses: Vec<String>,
    /// Generous backstop cap on total members in this pool (H2). `None` ⇒ no
    /// cap. Size it well above the real fleet - a tight cap fails *unsafe*
    /// (it locks out legitimate new capacity). Pair with short TTLs + alerting.
    #[serde(default)]
    pub max_members: Option<u32>,
    /// Cap on instances per service subtree, i.e. per `reg.<ns>.<service>.*`
    /// (H2 - the surgical anti-abuse control). `None` ⇒ no cap.
    #[serde(default)]
    pub max_instances_per_service: Option<u32>,
}

/// Forward / egress proxy listener configuration.
///
/// quik is primarily a reverse proxy; this is an opt-in second role on a
/// separate port. Only HTTP `CONNECT` is supported (not absolute-URI
/// forwarding) - appropriate for filtering outbound HTTPS traffic. SNI
/// sniffing peeks at the TLS ClientHello on the tunnel for logging, and
/// optionally enforces that the SNI matches the CONNECT target.
#[derive(Debug, Deserialize)]
pub struct EgressConfig {
    pub bind: SocketAddr,
    /// What to do for a CONNECT target that no rule matches.
    /// Default: `deny` (safer for security-oriented deployments).
    #[serde(default = "default_egress_action")]
    pub default_action: EgressAction,
    /// If true, abort the tunnel when the TLS ClientHello's SNI doesn't
    /// match the CONNECT target host. If false (default), log a warning
    /// and continue - useful for initial observability before tightening.
    #[serde(default)]
    pub sni_enforce: bool,
    /// First-match-wins rule list. A rule matches if the request hits
    /// any of its hosts OR any of its cidrs.
    #[serde(default)]
    pub rules: Vec<EgressRuleConfig>,
    /// Optional proxy authentication. When set, every CONNECT request must
    /// carry a matching `Proxy-Authorization` header - missing/invalid
    /// auth gets a `407 Proxy Authentication Required` challenge.
    #[serde(default)]
    pub auth: Option<EgressAuthConfig>,
}

/// How the egress proxy identifies its caller.
///
/// Two modes:
/// - **Jwt**: cryptographic validation against an existing `[[auth]]` block
///   (full token verification, kid resolution, etc. - same machinery the
///   reverse-proxy uses on `/secure` routes). The `originator_claim` value
///   is extracted from the verified token and logged.
/// - **BasicLogOnly**: the client must send HTTP Basic auth, but we
///   *don't validate the password*. We just decode the username and log
///   it as the originator. Appropriate only for closed networks where the
///   network itself is the security boundary - the audit trail tells you
///   what a user *claimed* to be, not what they cryptographically proved.
#[derive(Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum EgressAuthConfig {
    Jwt {
        /// References an `[[auth]] name = "…"` block.
        block: String,
        /// Claim to extract as the logged originator. Default: `sub`.
        #[serde(default = "default_originator_claim")]
        originator_claim: String,
    },
    BasicLogOnly {
        /// Realm string for the `407` challenge - appears in browser auth
        /// prompts and curl's prompts.
        realm: String,
    },
}

fn default_originator_claim() -> String {
    "sub".to_string()
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EgressAction {
    Allow,
    #[default]
    Deny,
}

fn default_egress_action() -> EgressAction {
    EgressAction::Deny
}

#[derive(Debug, Deserialize)]
pub struct EgressRuleConfig {
    pub action: EgressAction,
    /// Host patterns: exact (`github.com`) or wildcard subdomain
    /// (`*.github.com`). Matched against the CONNECT target's hostname
    /// - and, separately, against the SNI when present.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// CIDR patterns (`192.168.0.0/16`, `2001:db8::/32`) and IP literals.
    /// Matched against IP-literal CONNECT targets directly, and against
    /// DNS-resolved IPs of hostname targets.
    #[serde(default)]
    pub cidrs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthBlockConfig {
    pub name: String,
    pub jwks_url: String,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    /// Allowed signing algorithms. Default: RS256, ES256, EdDSA.
    #[serde(default)]
    pub algorithms: Vec<String>,
    /// Claim names that must be present in the token. Default: empty.
    #[serde(default)]
    pub required_claims: Vec<String>,
    /// Map claims from the verified JWT into headers on the upstream-bound
    /// request. Each mapping is applied after signature verification. The
    /// proxy unconditionally removes the mapped header from the inbound
    /// request before inserting its value - clients cannot spoof these
    /// headers by setting them themselves.
    #[serde(default)]
    pub inject_headers: Vec<ClaimHeaderMapping>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClaimHeaderMapping {
    /// Top-level claim name in the JWT payload. JWT issuers commonly use
    /// fully-qualified URLs as claim names (e.g.
    /// `https://example.com/tenant_id`) - those are matched literally, not
    /// as dotted paths.
    pub claim: String,
    /// HTTP header name to set on the upstream-bound request.
    pub header: String,
    /// If true and the claim is absent from the token, the request is
    /// rejected with 403. Default: false (skip silently).
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Edge,
    Host,
}

#[derive(Debug, Deserialize)]
pub struct ListenerConfig {
    pub bind: SocketAddr,
    pub tls: TlsConfig,
    /// Defensive connection-level timeouts and HTTP/2 frame limits. Defaults
    /// are appropriate for a proxy behind a trusted load balancer; tighten
    /// them when exposing directly to untrusted clients.
    #[serde(default)]
    pub limits: ListenerLimitsConfig,
}

#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// Per-listener defensive timeouts and protocol-level limits. Each field is
/// optional - unset means "use hyper-util's default", which is usually
/// permissive. The shipped defaults below tighten where the hyper defaults
/// are open-ended (header read, h2 concurrency).
#[derive(Debug, Clone, Deserialize)]
pub struct ListenerLimitsConfig {
    /// Time the proxy waits to receive the full HTTP/1.1 request headers
    /// before closing the connection. Mitigates slowloris (one byte at a
    /// time header attacks). Default: 30_000 (30 s). Set 0 to disable.
    #[serde(default = "default_header_read_timeout_ms")]
    pub header_read_timeout_ms: u64,
    /// Interval at which the server sends HTTP/2 PING frames on otherwise
    /// idle connections to detect dead peers. Useful for long-lived gRPC /
    /// streaming clients behind NAT timeouts. Default: 0 (disabled).
    #[serde(default)]
    pub http2_keep_alive_interval_ms: u64,
    /// Time the server waits for a PING response before considering the
    /// connection dead and closing it. Only meaningful when
    /// `http2_keep_alive_interval_ms > 0`. Default: 20_000.
    #[serde(default = "default_http2_keep_alive_timeout_ms")]
    pub http2_keep_alive_timeout_ms: u64,
    /// Max concurrent HTTP/2 streams per inbound connection. Bounds memory
    /// and goroutine-equivalent task count one client can hold. Default: 256.
    #[serde(default = "default_http2_max_concurrent_streams")]
    pub http2_max_concurrent_streams: u32,
    /// Max number of locally-reset streams kept in memory (RFC 9113 §5.1.2).
    /// Mitigates CVE-2023-44487 ("Rapid Reset"). Default: 64.
    #[serde(default = "default_http2_max_concurrent_reset_streams")]
    pub http2_max_concurrent_reset_streams: usize,
    /// How long an established WebSocket tunnel may sit idle (no bytes in
    /// either direction) before the proxy closes it. Set 0 to disable.
    /// Default: 300_000 (5 min). Long-lived chat / control protocols
    /// usually send pings; tunnels with no application-level keepalive
    /// will be culled.
    #[serde(default = "default_ws_idle_timeout_ms")]
    pub websocket_idle_timeout_ms: u64,
}

impl Default for ListenerLimitsConfig {
    fn default() -> Self {
        Self {
            header_read_timeout_ms: default_header_read_timeout_ms(),
            http2_keep_alive_interval_ms: 0,
            http2_keep_alive_timeout_ms: default_http2_keep_alive_timeout_ms(),
            http2_max_concurrent_streams: default_http2_max_concurrent_streams(),
            http2_max_concurrent_reset_streams: default_http2_max_concurrent_reset_streams(),
            websocket_idle_timeout_ms: default_ws_idle_timeout_ms(),
        }
    }
}

fn default_header_read_timeout_ms() -> u64 {
    30_000
}
fn default_http2_keep_alive_timeout_ms() -> u64 {
    20_000
}
fn default_http2_max_concurrent_streams() -> u32 {
    256
}
fn default_http2_max_concurrent_reset_streams() -> usize {
    64
}
fn default_ws_idle_timeout_ms() -> u64 {
    300_000
}

#[derive(Debug, Deserialize)]
pub struct AdminConfig {
    pub bind: SocketAddr,
    /// Optional TLS for the admin listener. If any of the `auth` groups uses
    /// `mtls`, this MUST be set - mTLS implies the listener itself is TLS.
    /// If set but no group is mTLS, the listener is plain TLS with no
    /// client-cert requirement.
    #[serde(default)]
    pub tls: Option<AdminTlsConfig>,
    /// Per-endpoint-group auth (read vs write). Defaults to `None` on both,
    /// leaving the admin listener open - appropriate only behind a trusted
    /// network boundary.
    #[serde(default)]
    pub auth: AdminAuthGroups,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminTlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// Optional CA bundle used to validate client certificates. Set only
    /// when an auth group uses `mtls`. Same file format as `cert_path` (PEM).
    #[serde(default)]
    pub client_ca_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Default)]
pub struct AdminAuthGroups {
    /// Auth applied to GET endpoints. Default: `none` - reads are open by
    /// default because they expose the same data as `/metrics`.
    #[serde(default)]
    pub read: AdminAuthConfig,
    /// Auth applied to mutating endpoints (POST/DELETE). Default: `none` but
    /// strongly recommended to set in production.
    #[serde(default)]
    pub write: AdminAuthConfig,
}

#[derive(Debug, Deserialize, Default)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum AdminAuthConfig {
    /// No authentication. Default - appropriate for read endpoints behind a
    /// trusted network boundary; reckless for write endpoints.
    #[default]
    None,
    /// HTTP `Authorization: Bearer <token>`. The token is read from the
    /// named environment variable at startup and compared byte-equal.
    BearerToken {
        /// Name of the env var containing the token. Read once at startup.
        token_env: String,
    },
    /// mTLS - client must present a certificate validated against the
    /// admin TLS block's `client_ca_path`. The verified subject DN is
    /// recorded in the audit log as `authn_principal`.
    Mtls,
}

#[derive(Debug, Deserialize)]
pub struct ShutdownConfig {
    #[serde(default = "default_drain_secs")]
    pub drain_grace_seconds: u64,
    /// Edge-withdraw grace. On SIGTERM, `/healthz` flips to 503 immediately but
    /// the proxy keeps accepting for this long *before* the local drain begins,
    /// giving a perimeter (e.g. Cloudflare) time to notice the 503 and stop
    /// routing. See `docs/graceful-shutdown.md`. Default: 0 - disabled, so behaviour
    /// matches a proxy without an edge in front (drain begins immediately).
    #[serde(default = "default_pre_drain_secs")]
    pub pre_drain_grace_seconds: u64,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            drain_grace_seconds: default_drain_secs(),
            pre_drain_grace_seconds: default_pre_drain_secs(),
        }
    }
}

fn default_drain_secs() -> u64 {
    30
}

fn default_pre_drain_secs() -> u64 {
    0
}

#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Output format. `json` is machine-parseable (one JSON object per line);
    /// `key_value` is a more human-readable single-line format with
    /// `field=value` pairs. Default: json.
    #[serde(default)]
    pub format: LogFormat,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    #[default]
    Json,
    KeyValue,
}

fn default_log_level() -> String {
    "info,quik=info".to_string()
}

#[derive(Debug, Deserialize)]
pub struct UpstreamPoolConfig {
    pub name: String,
    /// Static members. Optional - a NATS-backed pool (`[upstreams.nats]`) omits
    /// these and is populated at runtime. `validate()` rejects an empty pool
    /// that has no runtime source.
    #[serde(default)]
    pub members: Vec<UpstreamMember>,
    #[serde(default)]
    pub balancer: BalancerKind,
    #[serde(default)]
    pub tls: UpstreamTlsConfig,
    #[serde(default)]
    pub health: UpstreamHealthConfig,
    /// HTTP version used on the proxy→upstream connection. Default H1 -
    /// universally compatible. Opt into H2 only for backends that you've
    /// verified speak HTTP/2 (e.g. gRPC services). The inbound client's
    /// version is unrelated; quik translates between protocols at the hop.
    #[serde(default)]
    pub http_version: UpstreamHttpVersion,
    /// Active health checks. Default: disabled - pools without explicit
    /// config stay on passive health only.
    #[serde(default)]
    pub active_health: ActiveHealthConfig,
    /// Drain settings. Used when a member is removed via the admin API.
    #[serde(default)]
    pub drain: DrainConfig,
    /// Connection-pool tuning for the proxy→upstream hyper client.
    #[serde(default)]
    pub pool: UpstreamClientPoolConfig,
    /// Optional NATS registration binding. When set, this pool is populated
    /// from a KV subtree at runtime and may start with no static `members`.
    #[serde(default)]
    pub nats: Option<UpstreamNatsConfig>,
}

/// Per-pool tuning of the hyper client's idle connection pool. Defaults
/// match the historical hardcoded values; tighten for memory-constrained
/// hosts or loosen for hot pools handling many small requests.
#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamClientPoolConfig {
    /// How long an idle connection is kept in the pool before being closed.
    /// Default: 60_000 (60 s).
    #[serde(default = "default_pool_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    /// Max idle connections retained per backend host. Default: 100.
    #[serde(default = "default_pool_max_idle_per_host")]
    pub max_idle_per_host: usize,
}

impl Default for UpstreamClientPoolConfig {
    fn default() -> Self {
        Self {
            idle_timeout_ms: default_pool_idle_timeout_ms(),
            max_idle_per_host: default_pool_max_idle_per_host(),
        }
    }
}

fn default_pool_idle_timeout_ms() -> u64 {
    60_000
}
fn default_pool_max_idle_per_host() -> usize {
    100
}

/// Per-pool active health check configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ActiveHealthConfig {
    /// Default: false. When false, no probe task is spawned and the
    /// per-member `ActiveHealth` is constructed in "disabled" mode (always
    /// eligible). When true, a single probe task per pool drives the
    /// `ActiveHealth` state machine.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_active_path")]
    pub path: String,
    #[serde(default = "default_active_method")]
    pub method: String,
    #[serde(default = "default_active_interval_ms")]
    pub interval_ms: u64,
    #[serde(default = "default_active_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
    /// Status code or range string ("200-299"). Accepts either an integer or
    /// a string at parse time.
    #[serde(default = "default_expected_status")]
    pub expected_status: StatusMatcher,
    /// Pessimistic (`unhealthy`, default) means members don't take traffic
    /// until probes succeed enough. Optimistic (`healthy`) means traffic
    /// flows immediately and only stops if probes fail.
    #[serde(default)]
    pub initial_state: InitialActiveState,
}

impl Default for ActiveHealthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_active_path(),
            method: default_active_method(),
            interval_ms: default_active_interval_ms(),
            timeout_ms: default_active_timeout_ms(),
            healthy_threshold: default_healthy_threshold(),
            unhealthy_threshold: default_unhealthy_threshold(),
            expected_status: default_expected_status(),
            initial_state: InitialActiveState::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InitialActiveState {
    #[default]
    Unhealthy,
    Healthy,
}

/// HTTP status matcher accepting either an integer (`200`) or a range string
/// (`"200-299"`). Stored as either form to preserve operator intent in the
/// admin API response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusMatcher {
    Exact(u16),
    Range(u16, u16),
}

impl StatusMatcher {
    pub fn matches(&self, status: u16) -> bool {
        match self {
            StatusMatcher::Exact(s) => *s == status,
            StatusMatcher::Range(lo, hi) => status >= *lo && status <= *hi,
        }
    }
}

impl<'de> Deserialize<'de> for StatusMatcher {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = StatusMatcher;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("HTTP status code (integer) or range string like \"200-299\"")
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                if v > u16::MAX as u64 {
                    return Err(E::custom("status code out of u16 range"));
                }
                Ok(StatusMatcher::Exact(v as u16))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                if !(0..=u16::MAX as i64).contains(&v) {
                    return Err(E::custom("status code out of u16 range"));
                }
                Ok(StatusMatcher::Exact(v as u16))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                parse_status_matcher(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_any(V)
    }
}

fn parse_status_matcher(s: &str) -> Result<StatusMatcher, String> {
    if let Some((lo_s, hi_s)) = s.split_once('-') {
        let lo: u16 = lo_s
            .trim()
            .parse()
            .map_err(|_| format!("invalid status range low end: {lo_s:?}"))?;
        let hi: u16 = hi_s
            .trim()
            .parse()
            .map_err(|_| format!("invalid status range high end: {hi_s:?}"))?;
        if lo > hi {
            return Err(format!("status range low > high: {lo} > {hi}"));
        }
        Ok(StatusMatcher::Range(lo, hi))
    } else {
        s.trim()
            .parse::<u16>()
            .map(StatusMatcher::Exact)
            .map_err(|_| format!("invalid status code: {s:?}"))
    }
}

fn default_active_path() -> String {
    "/healthz".to_string()
}
fn default_active_method() -> String {
    "GET".to_string()
}
fn default_active_interval_ms() -> u64 {
    10_000
}
fn default_active_timeout_ms() -> u64 {
    2_000
}
fn default_healthy_threshold() -> u32 {
    2
}
fn default_unhealthy_threshold() -> u32 {
    3
}
fn default_expected_status() -> StatusMatcher {
    StatusMatcher::Exact(200)
}

#[derive(Debug, Clone, Deserialize)]
pub struct DrainConfig {
    #[serde(default = "default_drain_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for DrainConfig {
    fn default() -> Self {
        Self {
            timeout_ms: default_drain_timeout_ms(),
        }
    }
}

fn default_drain_timeout_ms() -> u64 {
    60_000
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamHttpVersion {
    #[default]
    H1,
    H2,
}

#[derive(Debug, Default, Deserialize)]
pub struct UpstreamTlsConfig {
    /// DANGER: bypass server certificate verification for this pool's
    /// HTTPS upstreams. Only use on trusted internal networks or with
    /// self-signed certs in test environments. Default: false.
    #[serde(default)]
    pub skip_verify: bool,
}

/// Per-pool passive health (outlier detection) tuning. The proxy ejects a
/// member after `ejection_threshold` consecutive failures (5xx, timeout, or
/// connect error) and exponentially backs off subsequent re-admissions.
#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamHealthConfig {
    #[serde(default = "default_ejection_threshold")]
    pub ejection_threshold: u32,
    #[serde(default = "default_ejection_base_ms")]
    pub ejection_base_ms: u64,
    #[serde(default = "default_ejection_max_ms")]
    pub ejection_max_ms: u64,
}

impl Default for UpstreamHealthConfig {
    fn default() -> Self {
        Self {
            ejection_threshold: default_ejection_threshold(),
            ejection_base_ms: default_ejection_base_ms(),
            ejection_max_ms: default_ejection_max_ms(),
        }
    }
}

fn default_ejection_threshold() -> u32 {
    5
}
fn default_ejection_base_ms() -> u64 {
    1_000
}
fn default_ejection_max_ms() -> u64 {
    60_000
}

#[derive(Debug, Deserialize)]
pub struct UpstreamMember {
    pub address: String,
    #[serde(default = "default_scheme")]
    pub scheme: String,
}

fn default_scheme() -> String {
    "http".to_string()
}

#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BalancerKind {
    #[default]
    RoundRobin,
    Random,
    LeastConnections,
}

#[derive(Debug, Default, Deserialize)]
pub struct RouteConfig {
    /// Singular form, kept for backward compat. `hosts` is the preferred plural.
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub hosts: Vec<String>,

    /// Singular form, kept for backward compat. `methods` is the preferred plural.
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub methods: Vec<String>,

    /// Exact-match path. Mutually exclusive with `path_prefix`. Higher
    /// precedence than any prefix match.
    #[serde(default)]
    pub path_exact: Option<String>,
    /// Prefix-match path (segment-aware: `/api` matches `/api`, `/api/x`, never
    /// `/apifoo`). Defaults to `/` if neither path field is set.
    #[serde(default)]
    pub path_prefix: Option<String>,

    // ── modules ────────────────────────────────────────────────────────────
    /// Strip this prefix from the path before forwarding upstream.
    #[serde(default)]
    pub strip_prefix: Option<String>,
    /// Upper bound on upstream response time. 504 on expiry.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Cap inbound request body size (via Content-Length). 413 if exceeded.
    #[serde(default)]
    pub max_body_bytes: Option<u64>,
    /// Name of an `[[auth]]` block to apply to requests on this route.
    /// Missing/invalid token → 401. Missing required claim → 403.
    #[serde(default)]
    pub auth: Option<String>,

    pub upstream: String,
}

impl RouteConfig {
    /// Combine the singular `host` field and the plural `hosts` field into one
    /// list. Returns empty vec to mean "match any host".
    pub fn all_hosts(&self) -> Vec<String> {
        let mut out = Vec::with_capacity(self.hosts.len() + 1);
        if let Some(h) = &self.host {
            out.push(h.clone());
        }
        out.extend(self.hosts.iter().cloned());
        out
    }

    pub fn all_methods(&self) -> Vec<String> {
        let mut out = Vec::with_capacity(self.methods.len() + 1);
        if let Some(m) = &self.method {
            out.push(m.clone());
        }
        out.extend(self.methods.iter().cloned());
        out
    }

    /// Short string used in validation error messages.
    pub fn summary(&self) -> String {
        let path = self
            .path_exact
            .as_deref()
            .or(self.path_prefix.as_deref())
            .unwrap_or("/");
        let host = self
            .host
            .as_deref()
            .or_else(|| self.hosts.first().map(String::as_str))
            .unwrap_or("*");
        format!("{host}{path}")
    }
}

pub fn load(path: &Path) -> Result<Config> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let expanded =
        expand_env(&text).with_context(|| format!("expanding env vars in {}", path.display()))?;
    let cfg: Config =
        toml::from_str(&expanded).with_context(|| format!("parsing TOML at {}", path.display()))?;
    validate(&cfg)?;
    Ok(cfg)
}

/// Expand `${VAR}` and `${VAR:-default}` into env values inside the raw config
/// text, before TOML parsing. Errors if a referenced variable is missing and
/// no default is provided.
pub fn expand_env(input: &str) -> Result<String> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| anyhow::anyhow!("unterminated ${{ in config"))?;
        let inner = &after[..end];
        let (name, default) = match inner.find(":-") {
            Some(p) => (&inner[..p], Some(&inner[p + 2..])),
            None => (inner, None),
        };
        match std::env::var(name) {
            Ok(v) => out.push_str(&v),
            Err(_) => match default {
                Some(d) => out.push_str(d),
                None => anyhow::bail!("config references undefined env var: {}", name),
            },
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn validate(cfg: &Config) -> Result<()> {
    let names: HashSet<&str> = cfg.upstreams.iter().map(|u| u.name.as_str()).collect();
    if names.len() != cfg.upstreams.len() {
        anyhow::bail!("duplicate upstream pool names");
    }
    let auth_names: HashSet<&str> = cfg.auth.iter().map(|a| a.name.as_str()).collect();
    if auth_names.len() != cfg.auth.len() {
        anyhow::bail!("duplicate auth block names");
    }
    for r in &cfg.routes {
        if !names.contains(r.upstream.as_str()) {
            anyhow::bail!(
                "route '{}' references unknown upstream pool '{}'",
                r.summary(),
                r.upstream
            );
        }
        if let Some(a) = &r.auth
            && !auth_names.contains(a.as_str())
        {
            anyhow::bail!("route '{}' references unknown auth '{}'", r.summary(), a);
        }
        if r.path_exact.is_some() && r.path_prefix.is_some() {
            anyhow::bail!(
                "route '{}': set either path_exact or path_prefix, not both",
                r.summary()
            );
        }
        if let Some(p) = &r.path_prefix
            && !p.starts_with('/')
        {
            anyhow::bail!("route '{}': path_prefix must start with '/'", r.summary());
        }
        if let Some(p) = &r.path_exact
            && !p.starts_with('/')
        {
            anyhow::bail!("route '{}': path_exact must start with '/'", r.summary());
        }
        if let Some(s) = &r.strip_prefix
            && !s.starts_with('/')
        {
            anyhow::bail!("route '{}': strip_prefix must start with '/'", r.summary());
        }
    }
    // A binary built without the `nats` feature cannot act on NATS config -
    // fail fast rather than silently leaving NATS-backed pools empty forever.
    #[cfg(not(feature = "nats"))]
    {
        if cfg.nats.is_some() || cfg.upstreams.iter().any(|u| u.nats.is_some()) {
            anyhow::bail!(
                "config uses [nats]/[upstreams.nats] but this binary was built \
                 without the `nats` feature (rebuild with --features nats)"
            );
        }
    }
    // A pool can only register members if there's a NATS connection to watch.
    if cfg.upstreams.iter().any(|u| u.nats.is_some()) && cfg.nats.is_none() {
        anyhow::bail!("[upstreams.nats] is set but the top-level [nats] block is missing");
    }

    for u in &cfg.upstreams {
        // A pool may start empty only if it is populated from NATS at runtime.
        if u.members.is_empty() && u.nats.is_none() {
            anyhow::bail!("upstream pool '{}' has no members", u.name);
        }
        if let Some(n) = &u.nats {
            if n.subject.trim().is_empty() {
                anyhow::bail!(
                    "upstream pool '{}': [upstreams.nats].subject is empty",
                    u.name
                );
            }
            // Must be a subtree wildcard, not a literal key - otherwise the
            // watcher silently matches nothing useful (a forgotten `.>`).
            if !n.subject.ends_with('>') && !n.subject.ends_with('*') {
                anyhow::bail!(
                    "upstream pool '{}': [upstreams.nats].subject must end with a wildcard \
                     token (e.g. 'reg.<ns>.<service>.>'), not a literal key",
                    u.name
                );
            }
            // ...but a *bare* wildcard ('>' / '.>' / '*') leaves an empty literal
            // prefix, which matches no key - the pool would silently stay empty.
            // Require at least one literal token before the wildcard.
            if n.subject
                .trim_end_matches(['>', '*'])
                .trim_end_matches('.')
                .is_empty()
            {
                anyhow::bail!(
                    "upstream pool '{}': [upstreams.nats].subject needs a literal prefix before \
                     the wildcard (e.g. 'reg.<ns>.<service>.>'), not a bare '>' or '*'",
                    u.name
                );
            }
            // SECURITY (H1, fail-safe): an empty allow-list would admit any
            // self-asserted address (SSRF / traffic hijack), so it is rejected at
            // config load - a NATS pool must state where members may live. Too
            // strict merely refuses a registration; too loose is a vulnerability.
            if n.allow_addresses.is_empty() {
                anyhow::bail!(
                    "upstream pool '{}': [upstreams.nats].allow_addresses must list at least \
                     one CIDR or host-suffix - self-registered addresses are otherwise unbounded",
                    u.name
                );
            }
        }
        for m in &u.members {
            if m.scheme != "http" && m.scheme != "https" {
                anyhow::bail!(
                    "upstream pool '{}': scheme must be 'http' or 'https', got '{}'",
                    u.name,
                    m.scheme
                );
            }
        }
        if u.active_health.enabled {
            if u.active_health.healthy_threshold == 0 {
                anyhow::bail!(
                    "upstream pool '{}': active_health.healthy_threshold must be ≥ 1",
                    u.name
                );
            }
            if u.active_health.unhealthy_threshold == 0 {
                anyhow::bail!(
                    "upstream pool '{}': active_health.unhealthy_threshold must be ≥ 1",
                    u.name
                );
            }
            // Validate the HTTP method as soon as possible; it's a one-line
            // typo that's easy to make in TOML.
            if u.active_health.method.parse::<http::Method>().is_err() {
                anyhow::bail!(
                    "upstream pool '{}': active_health.method '{}' is not a valid HTTP method",
                    u.name,
                    u.active_health.method
                );
            }
        }
    }
    // Admin auth: mTLS requires the admin TLS block AND a client_ca_path on it.
    let uses_mtls = matches!(cfg.admin.auth.read, AdminAuthConfig::Mtls)
        || matches!(cfg.admin.auth.write, AdminAuthConfig::Mtls);
    if uses_mtls {
        let Some(tls) = &cfg.admin.tls else {
            anyhow::bail!(
                "admin.auth uses mtls but [admin.tls] is not configured - mTLS requires TLS"
            );
        };
        if tls.client_ca_path.is_none() {
            anyhow::bail!("admin.auth uses mtls but [admin.tls].client_ca_path is not set");
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(unsafe_code)] // env::set_var is `unsafe` in edition 2024; unit tests need it.
mod tests {
    use super::*;

    const MIN: &str = r#"
[listener]
bind = "127.0.0.1:8443"
[listener.tls]
cert_path = "c.pem"
key_path  = "k.pem"
[admin]
bind = "127.0.0.1:9090"
"#;

    #[test]
    fn parses_minimum_config() {
        let s = format!(
            "{MIN}\n[[upstreams]]\nname=\"a\"\nmembers=[{{address=\"127.0.0.1:1\"}}]\n\
             [[routes]]\npath_prefix=\"/x\"\nupstream=\"a\"\n"
        );
        let cfg: Config = toml::from_str(&s).unwrap();
        validate(&cfg).unwrap();
        assert_eq!(cfg.upstreams.len(), 1);
        assert_eq!(cfg.routes.len(), 1);
        assert_eq!(cfg.shutdown.drain_grace_seconds, 30);
    }

    #[test]
    fn rejects_route_with_unknown_upstream() {
        let s = format!(
            "{MIN}\n[[upstreams]]\nname=\"a\"\nmembers=[{{address=\"127.0.0.1:1\"}}]\n\
             [[routes]]\npath_prefix=\"/x\"\nupstream=\"ghost\"\n"
        );
        let cfg: Config = toml::from_str(&s).unwrap();
        let err = validate(&cfg).unwrap_err();
        assert!(err.to_string().contains("unknown upstream"), "{err}");
    }

    #[test]
    fn rejects_duplicate_upstream_names() {
        let s = format!(
            "{MIN}\n[[upstreams]]\nname=\"a\"\nmembers=[{{address=\"127.0.0.1:1\"}}]\n\
             [[upstreams]]\nname=\"a\"\nmembers=[{{address=\"127.0.0.1:2\"}}]\n"
        );
        let cfg: Config = toml::from_str(&s).unwrap();
        let err = validate(&cfg).unwrap_err();
        assert!(err.to_string().contains("duplicate"), "{err}");
    }

    #[test]
    fn rejects_path_prefix_without_leading_slash() {
        let s = format!(
            "{MIN}\n[[upstreams]]\nname=\"a\"\nmembers=[{{address=\"127.0.0.1:1\"}}]\n\
             [[routes]]\npath_prefix=\"api\"\nupstream=\"a\"\n"
        );
        let cfg: Config = toml::from_str(&s).unwrap();
        let err = validate(&cfg).unwrap_err();
        assert!(err.to_string().contains("must start with"), "{err}");
    }

    #[test]
    fn env_expansion_with_default() {
        // SAFETY: setting env vars is non-thread-safe in std; cargo runs unit
        // tests in one process, but we use a unique name to avoid collisions.
        unsafe {
            std::env::remove_var("QUIK_TEST_UNSET_VAR_1234");
        }
        let out = expand_env("addr = \"${QUIK_TEST_UNSET_VAR_1234:-127.0.0.1:9000}\"").unwrap();
        assert_eq!(out, "addr = \"127.0.0.1:9000\"");
    }

    #[test]
    fn env_expansion_with_set_var() {
        unsafe {
            std::env::set_var("QUIK_TEST_SET_VAR_5678", "10.0.0.1:8080");
        }
        let out = expand_env("addr = \"${QUIK_TEST_SET_VAR_5678}\"").unwrap();
        assert_eq!(out, "addr = \"10.0.0.1:8080\"");
        unsafe {
            std::env::remove_var("QUIK_TEST_SET_VAR_5678");
        }
    }

    #[test]
    fn env_expansion_errors_on_unset_no_default() {
        unsafe {
            std::env::remove_var("QUIK_TEST_MISSING_VAR_9999");
        }
        let err = expand_env("addr = \"${QUIK_TEST_MISSING_VAR_9999}\"").unwrap_err();
        assert!(err.to_string().contains("undefined env var"), "{err}");
    }

    #[test]
    fn status_matcher_accepts_integer_or_range() {
        // Integer form.
        let s = format!(
            "{MIN}\n[[upstreams]]\nname=\"a\"\nmembers=[{{address=\"127.0.0.1:1\"}}]\n\
             [upstreams.active_health]\nenabled=true\nexpected_status=204\n\
             [[routes]]\npath_prefix=\"/x\"\nupstream=\"a\"\n"
        );
        let cfg: Config = toml::from_str(&s).unwrap();
        validate(&cfg).unwrap();
        let m = &cfg.upstreams[0].active_health.expected_status;
        assert_eq!(*m, StatusMatcher::Exact(204));
        assert!(m.matches(204));
        assert!(!m.matches(200));

        // Range form.
        let s = format!(
            "{MIN}\n[[upstreams]]\nname=\"a\"\nmembers=[{{address=\"127.0.0.1:1\"}}]\n\
             [upstreams.active_health]\nenabled=true\nexpected_status=\"200-299\"\n\
             [[routes]]\npath_prefix=\"/x\"\nupstream=\"a\"\n"
        );
        let cfg: Config = toml::from_str(&s).unwrap();
        let m = &cfg.upstreams[0].active_health.expected_status;
        assert_eq!(*m, StatusMatcher::Range(200, 299));
        assert!(m.matches(204));
        assert!(!m.matches(300));
    }

    #[test]
    fn rejects_active_health_with_zero_threshold() {
        let s = format!(
            "{MIN}\n[[upstreams]]\nname=\"a\"\nmembers=[{{address=\"127.0.0.1:1\"}}]\n\
             [upstreams.active_health]\nenabled=true\nhealthy_threshold=0\n\
             [[routes]]\npath_prefix=\"/x\"\nupstream=\"a\"\n"
        );
        let cfg: Config = toml::from_str(&s).unwrap();
        let err = validate(&cfg).unwrap_err();
        assert!(err.to_string().contains("healthy_threshold"), "{err}");
    }

    #[test]
    fn rejects_mtls_without_tls_block() {
        let s = format!(
            "{MIN}\n[admin.auth.write]\nmode=\"mtls\"\n\
             [[upstreams]]\nname=\"a\"\nmembers=[{{address=\"127.0.0.1:1\"}}]\n\
             [[routes]]\npath_prefix=\"/x\"\nupstream=\"a\"\n"
        );
        let cfg: Config = toml::from_str(&s).unwrap();
        let err = validate(&cfg).unwrap_err();
        assert!(err.to_string().contains("mtls"), "{err}");
    }

    #[test]
    fn accepts_bearer_token_auth() {
        let s = format!(
            "{MIN}\n[admin.auth.write]\nmode=\"bearer_token\"\ntoken_env=\"X_QUIK_TEST\"\n\
             [[upstreams]]\nname=\"a\"\nmembers=[{{address=\"127.0.0.1:1\"}}]\n\
             [[routes]]\npath_prefix=\"/x\"\nupstream=\"a\"\n"
        );
        let cfg: Config = toml::from_str(&s).unwrap();
        validate(&cfg).unwrap();
        match &cfg.admin.auth.write {
            AdminAuthConfig::BearerToken { token_env } => assert_eq!(token_env, "X_QUIK_TEST"),
            other => panic!("expected BearerToken, got {other:?}"),
        }
    }

    #[test]
    fn default_drain_timeout_is_60_seconds() {
        let s = format!(
            "{MIN}\n[[upstreams]]\nname=\"a\"\nmembers=[{{address=\"127.0.0.1:1\"}}]\n\
             [[routes]]\npath_prefix=\"/x\"\nupstream=\"a\"\n"
        );
        let cfg: Config = toml::from_str(&s).unwrap();
        assert_eq!(cfg.upstreams[0].drain.timeout_ms, 60_000);
    }

    #[test]
    fn rejects_empty_upstream_pool() {
        let s = format!(
            "{MIN}\n[[upstreams]]\nname=\"a\"\nmembers=[]\n\
             [[routes]]\npath_prefix=\"/x\"\nupstream=\"a\"\n"
        );
        let cfg: Config = toml::from_str(&s).unwrap();
        let err = validate(&cfg).unwrap_err();
        assert!(err.to_string().contains("no members"), "{err}");
    }
}
