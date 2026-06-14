//! Upstream pools, clients, passive health, and byte counting.
//!
//! Each `[[upstreams]]` block compiles to one [`UpstreamPoolEntry`]:
//! - a hyper client built specifically for this pool (so per-pool TLS knobs
//!   like `skip_verify` and the ALPN-matched HTTP version don't leak across
//!   services), and
//! - a [`Balancer`] trait object driving member selection.
//!
//! Non-obvious decisions:
//! - **Metric handles are pre-built per member.** `bytes_sent`, `bytes_received`,
//!   and `inflight_gauge` are constructed once and stored as cheap-to-clone
//!   `Arc` handles. The forward hot path doesn't allocate label strings for
//!   each emission. This requires the prometheus recorder to be installed
//!   BEFORE `Pool::from_config` - see `tests/common/install_metrics_recorder`.
//! - **[`CountingBody`] wraps every direction.** Byte counters are incremented
//!   per data frame so streaming uploads / downloads are attributed even
//!   without `Content-Length`.
//! - **[`InflightGuard`] is decrement-only.** The Balancer increments inside
//!   `pick()` so concurrent picks see the new value immediately; without
//!   that, a burst of arrivals would all see inflight=0 and stampede.
//! - **ALPN matches the request version.** Mismatch surfaces as hyper-util's
//!   `UserUnsupportedVersion`, so the connector advertises exactly one
//!   protocol per pool (see `build_client`).
//!
//! Lifecycle / active-health / drain machinery:
//! - [`state`] holds two orthogonal axes: [`state::MemberLifecycle`]
//!   (operator-controlled `active → draining → drained`) and
//!   [`state::ActiveHealth`] (probe-controlled `initial → healthy ↔ unhealthy`).
//! - [`probe`] runs one HTTP probe task per pool with `active_health.enabled`.
//! - [`drain`] runs one drain task per draining member; polls inflight to 0
//!   then either marks drained or removes from the pool's member list.
//! - `members` is an `ArcSwap<Vec<Arc<Upstream>>>` so admin writes can
//!   add/remove members without coordinating with the proxy hot path. The
//!   per-pool `write_lock` serialises writers; readers never take it.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use bytes::Bytes;
use http::uri::{Authority, Scheme};
use http_body_util::combinators::BoxBody;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

pub mod balance;
pub mod drain;
#[cfg(feature = "nats")]
pub mod nats;
pub mod probe;
pub mod state;

use crate::config::{
    ActiveHealthConfig, BalancerKind, Config, DrainConfig, InitialActiveState,
    UpstreamHealthConfig, UpstreamHttpVersion, UpstreamMember, UpstreamNatsConfig,
    UpstreamPoolConfig,
};
use balance::Balancer;

/// Wall-clock milliseconds since the UNIX epoch. Used by the health filter
/// to compare against ejection windows.
pub fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Errors flowing through the proxy body pipeline. Boxed so the same body
/// type can carry `hyper::Error` (from upstream / inbound reads) and our own
/// errors (e.g. `LengthLimitError` when `max_body_bytes` is exceeded).
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ProxyBody = BoxBody<Bytes, BoxError>;
pub type ProxyClient = Client<HttpsConnector<HttpConnector>, ProxyBody>;

/// Convert any body whose error implements `Into<BoxError>` into the uniform
/// `ProxyBody`. Used by both the proxy forwarder and the JWKS fetcher.
pub fn into_proxy_body<B>(body: B) -> ProxyBody
where
    B: hyper::body::Body<Data = Bytes> + Send + Sync + 'static,
    B::Error: Into<BoxError>,
{
    use http_body_util::BodyExt;
    body.map_err(Into::into).boxed()
}

/// `Body` wrapper that increments a `metrics::Counter` by the byte length
/// of every data frame as it streams through. Used on both directions of
/// the proxy hop to attribute bytes to the correct upstream member.
///
/// Trailer frames don't carry user data so they're not counted. Zero-length
/// or empty Bytes frames count 0 but still go through the macro path; that's
/// fine because Counter::increment(0) is a no-op (no atomic write under
/// the hood when the value is 0).
pub struct CountingBody<B> {
    inner: B,
    counter: metrics::Counter,
}

impl<B> CountingBody<B> {
    pub fn new(inner: B, counter: metrics::Counter) -> Self {
        Self { inner, counter }
    }
}

impl<B> hyper::body::Body for CountingBody<B>
where
    B: hyper::body::Body + Unpin,
    B::Data: bytes::Buf,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        use bytes::Buf;
        match std::pin::Pin::new(&mut self.inner).poll_frame(cx) {
            std::task::Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let n = data.remaining() as u64;
                    if n > 0 {
                        self.counter.increment(n);
                    }
                }
                std::task::Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// Snapshot the current pool map. Used by the periodic gauge sampler so it
/// doesn't have to hold an `ArcSwap` guard across the iteration.
impl Pool {
    pub fn snapshot(&self) -> Arc<HashMap<String, Arc<UpstreamPoolEntry>>> {
        self.pools.load_full()
    }
}

/// Build the per-member `ActiveHealth` from pool config. When `enabled=false`,
/// returns `disabled()` so `is_eligible()` is unconditionally true and the
/// pool keeps passive-health-only behaviour.
pub(crate) fn build_active_health(cfg: &ActiveHealthConfig) -> state::ActiveHealth {
    if !cfg.enabled {
        return state::ActiveHealth::disabled();
    }
    let initial = match cfg.initial_state {
        InitialActiveState::Healthy => state::ActiveHealthState::Healthy,
        InitialActiveState::Unhealthy => state::ActiveHealthState::Unhealthy,
    };
    state::ActiveHealth::new(cfg.healthy_threshold, cfg.unhealthy_threshold, initial)
}

/// Wrap a `Vec<Upstream>` into the storage shape used inside the pool entry.
/// `Arc<Vec<Arc<Upstream>>>` lets the proxy hot path load the member list
/// with a single Arc clone while admin writers can swap the list atomically.
/// (Unsized `Arc<[…]>` would be marginally tighter but isn't supported by
/// `arc_swap::RefCnt`.)
fn into_member_list(members: Vec<Upstream>) -> Arc<Vec<Arc<Upstream>>> {
    Arc::new(members.into_iter().map(Arc::new).collect())
}

/// Where a pool member came from. Surfaces in admin responses and the live
/// `/admin/config/snapshot` so operators can see at a glance which members
/// would survive a restart (Config) and which wouldn't (Runtime).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberSource {
    /// Present in the config file parsed at startup.
    Config,
    /// Added at runtime via the admin API. Lost on restart unless the
    /// operator copies the snapshot back into the config file.
    Runtime,
    /// Reconciled from the NATS registration bucket by the watcher. Owned by
    /// the watcher - only it may remove these; config/runtime members are never
    /// touched by reconciliation.
    Nats,
}

impl MemberSource {
    pub fn as_str(self) -> &'static str {
        match self {
            MemberSource::Config => "config",
            MemberSource::Runtime => "runtime",
            MemberSource::Nats => "nats",
        }
    }
}

pub struct Upstream {
    pub name: String,
    /// Bare upstream address (e.g. `127.0.0.1:8080` or `[::1]:8080`), used as
    /// the natural id in the admin API path and in audit log fields. Mirrors
    /// `authority.as_str()` for the common case but kept explicit so it's
    /// stable if `authority` ever gains a scheme or other adornment.
    pub address: String,
    pub authority: Authority,
    pub scheme: Scheme,
    /// Provenance: config-file vs admin-API-added. See [`MemberSource`].
    pub source: MemberSource,
    pub health: Arc<UpstreamHealth>,
    /// Active probe state. `disabled()` for members in pools where active
    /// checks aren't configured - `is_eligible()` is then unconditionally
    /// true and existing behaviour is preserved.
    pub active_health: Arc<state::ActiveHealth>,
    /// Operator-controlled lifecycle. `active` by default; transitions
    /// through `draining → drained` are driven by admin API calls.
    pub lifecycle: Arc<state::MemberLifecycle>,
    /// Pre-built metric handles per-member. Built once at pool construction
    /// so the hot path doesn't allocate label strings for every metric
    /// emission. `Counter` / `Gauge` are cheap-to-clone refcounted handles.
    pub bytes_sent: metrics::Counter,
    pub bytes_received: metrics::Counter,
    pub inflight_gauge: metrics::Gauge,
}

impl Upstream {
    /// Combined routing eligibility. AND of all three state axes: operator
    /// must not have marked the member draining/drained, passive health must
    /// not be in its backoff window, and active health must be passing (or
    /// disabled). Used by Balancer impls in place of the older single
    /// `health.is_eligible(now_ms)` check.
    pub fn is_routable(&self, now_ms: u64) -> bool {
        self.lifecycle.is_active()
            && self.health.is_eligible(now_ms)
            && self.active_health.is_eligible()
    }
}

/// Per-upstream passive health state. All fields are atomic so the LB hot
/// path can read them without locking. Ejection state is tracked as an
/// absolute "ejected until" wall-clock millisecond; eligibility is a single
/// load + comparison.
pub struct UpstreamHealth {
    /// Counter of consecutive failed requests; reset on any success.
    pub consecutive_failures: AtomicU32,
    /// Wall-clock ms after which this member is eligible again (0 = healthy).
    pub ejected_until_ms: AtomicU64,
    /// Monotonic counter of how many times this member has been ejected.
    /// Drives exponential backoff: each ejection doubles the cool-off.
    pub ejection_count: AtomicU32,
    /// Current in-flight request count. Used by `LeastConnections`.
    pub inflight: AtomicU32,

    // Cached thresholds from config so the hot path doesn't reach into
    // configuration for each `record_*` call.
    ejection_threshold: u32,
    ejection_base_ms: u64,
    ejection_max_ms: u64,
}

impl UpstreamHealth {
    pub fn new(cfg: &UpstreamHealthConfig) -> Self {
        Self {
            consecutive_failures: AtomicU32::new(0),
            ejected_until_ms: AtomicU64::new(0),
            ejection_count: AtomicU32::new(0),
            inflight: AtomicU32::new(0),
            ejection_threshold: cfg.ejection_threshold,
            ejection_base_ms: cfg.ejection_base_ms,
            ejection_max_ms: cfg.ejection_max_ms,
        }
    }

    /// Returns true if this member is currently eligible for selection.
    /// `now_ms` is passed in (rather than read inside) so a single pick call
    /// uses one consistent clock reading across all members.
    pub fn is_eligible(&self, now_ms: u64) -> bool {
        let ejected_until = self.ejected_until_ms.load(Ordering::Relaxed);
        ejected_until == 0 || now_ms >= ejected_until
    }

    /// Record a successful request. Resets the consecutive-failure counter
    /// and clears any active ejection window - a successful probe means
    /// the member has recovered. Returns true if this call transitioned
    /// the member out of an ejected state.
    pub fn record_success(&self) -> bool {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        let prev = self.ejected_until_ms.swap(0, Ordering::Relaxed);
        prev != 0
    }

    /// Record a failed request (5xx, connect error, or timeout). On the
    /// `ejection_threshold`-th consecutive failure, eject the member for
    /// an exponentially increasing window capped at `ejection_max_ms`.
    /// Returns true if this call caused the ejection so callers can fire
    /// metrics / logs without polluting the no-eject hot path.
    pub fn record_failure(&self) -> bool {
        let n = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if n == self.ejection_threshold {
            let count = self.ejection_count.fetch_add(1, Ordering::Relaxed);
            let backoff = self.compute_backoff(count);
            let until = unix_now_ms().saturating_add(backoff);
            self.ejected_until_ms.store(until, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    fn compute_backoff(&self, count: u32) -> u64 {
        // 1× base on first ejection, 2× on second, 4× on third, ..., capped.
        let shift = count.min(20);
        let raw = self.ejection_base_ms.checked_shl(shift).unwrap_or(u64::MAX);
        raw.min(self.ejection_max_ms)
    }
}

/// Decrement-only RAII guard for in-flight tracking. The increment happens
/// inside `Balancer::pick` so subsequent concurrent picks see the new
/// inflight value immediately - otherwise a burst of concurrent requests
/// could all see inflight=0 and stampede the same member.
pub struct InflightGuard {
    health: Arc<UpstreamHealth>,
}

impl InflightGuard {
    /// Build a guard for a member whose inflight was just incremented by
    /// `Balancer::pick`. The guard fires `inflight -= 1` on every exit
    /// path from `forward()`.
    pub fn for_picked(health: Arc<UpstreamHealth>) -> Self {
        Self { health }
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.health.inflight.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct UpstreamPoolEntry {
    /// Pool name, mirrored from the config key so admin API handlers and
    /// metric labelling can read it without a reverse lookup through the map.
    pub name: String,
    /// Live member list. Stored behind an `ArcSwap` so the proxy hot path
    /// loads the current list with a single Arc clone and the admin API's
    /// add/remove/drain writes a fresh list atomically without coordinating
    /// with in-flight requests. Members are wrapped in `Arc` so a writer can
    /// remove a member from the list while in-flight requests on that
    /// member continue to hold their own Arc to it.
    pub members: ArcSwap<Vec<Arc<Upstream>>>,
    pub balancer: Box<dyn Balancer>,
    /// Client for *this* pool. Per-pool so each pool can carry its own TLS
    /// settings (cert verification on/off, future per-pool timeouts, etc.)
    /// and so the connection pool inside hyper isn't shared across services
    /// that mustn't share connections.
    pub client: ProxyClient,
    /// What HTTP version to use on the upstream connection. Drives both the
    /// connector's ALPN advertisement and the version we stamp onto the
    /// outbound `Request`. They must match - ALPN-negotiated h1 with a
    /// request marked h2 produces hyper-util's `UserUnsupportedVersion`.
    pub http_version: UpstreamHttpVersion,
    /// Serialises admin writers (add / remove / drain). The hot path never
    /// takes this lock - it only loads the `members` snapshot. Mutexed write
    /// path lets us do load → clone → mutate → store without two writers
    /// racing into a torn slice.
    pub write_lock: tokio::sync::Mutex<()>,
    /// Per-pool active health check config. Cloned onto each new member at
    /// add-time so the probe task can read it without revisiting the global
    /// config. `enabled = false` means no probe task is spawned and members
    /// are constructed with `ActiveHealth::disabled()`.
    pub active_health_cfg: ActiveHealthConfig,
    /// Per-pool drain timeout config. Read by the drain task when a member
    /// is removed or drained via the admin API.
    pub drain_cfg: DrainConfig,
    /// Per-pool passive health config. Kept on the entry so the admin API
    /// can build new `Upstream` instances when adding members at runtime -
    /// otherwise we'd lose the operator's tuning on dynamic adds.
    pub health_cfg: UpstreamHealthConfig,
    /// Balancer name in human form, used for the admin API responses
    /// (the `balancer: Box<dyn Balancer>` field can't be downcast cheaply).
    pub balancer_name: BalancerKind,
    /// Per-pool NATS registration binding (subject + allow-list + caps), if the
    /// pool is NATS-backed. Read by the watcher; `None` for static pools.
    pub nats_cfg: Option<UpstreamNatsConfig>,
}

impl UpstreamPoolEntry {
    /// Build a new `Upstream` ready to be inserted into the members list.
    /// Used by the admin API's add-member handler. Constructs fresh metric
    /// handles + state machines using this pool's configured policies.
    pub fn build_member(&self, m: &UpstreamMember) -> Result<Upstream> {
        let authority: Authority = m
            .address
            .parse()
            .with_context(|| format!("invalid upstream address '{}'", m.address))?;
        let scheme: Scheme = m
            .scheme
            .parse()
            .with_context(|| format!("invalid scheme '{}'", m.scheme))?;
        if scheme != Scheme::HTTP && scheme != Scheme::HTTPS {
            anyhow::bail!("scheme must be 'http' or 'https', got '{}'", m.scheme);
        }
        let member_label = format!("{}@{}", self.name, m.address);
        let bytes_sent = metrics::counter!(
            "quik_upstream_bytes_sent_total",
            "pool" => self.name.clone(),
            "member" => member_label.clone(),
        );
        let bytes_received = metrics::counter!(
            "quik_upstream_bytes_received_total",
            "pool" => self.name.clone(),
            "member" => member_label.clone(),
        );
        let inflight_gauge = metrics::gauge!(
            "quik_upstream_inflight",
            "pool" => self.name.clone(),
            "member" => member_label.clone(),
        );
        Ok(Upstream {
            name: member_label,
            address: m.address.clone(),
            authority,
            scheme,
            source: MemberSource::Runtime,
            health: Arc::new(UpstreamHealth::new(&self.health_cfg)),
            active_health: Arc::new(build_active_health(&self.active_health_cfg)),
            lifecycle: Arc::new(state::MemberLifecycle::new()),
            bytes_sent,
            bytes_received,
            inflight_gauge,
        })
    }
}

impl UpstreamPoolEntry {
    /// Snapshot of the current member list. Cheap (single Arc clone). Hold
    /// the returned Arc for as long as you need the borrowed members - once
    /// you drop it, the list may be replaced by a writer.
    pub fn members_snapshot(&self) -> Arc<Vec<Arc<Upstream>>> {
        self.members.load_full()
    }
}

pub struct Pool {
    pools: ArcSwap<HashMap<String, Arc<UpstreamPoolEntry>>>,
}

impl Pool {
    pub fn from_config(cfg: &Config) -> Result<Self> {
        let pools = build_pools(cfg)?;
        Ok(Self {
            pools: ArcSwap::from_pointee(pools),
        })
    }

    pub fn get(&self, name: &str) -> Option<Arc<UpstreamPoolEntry>> {
        self.pools.load().get(name).cloned()
    }

    #[allow(dead_code)]
    pub fn swap(&self, new: HashMap<String, Arc<UpstreamPoolEntry>>) {
        self.pools.store(Arc::new(new));
    }
}

fn build_pools(cfg: &Config) -> Result<HashMap<String, Arc<UpstreamPoolEntry>>> {
    let mut out = HashMap::with_capacity(cfg.upstreams.len());
    for u in &cfg.upstreams {
        let mut members = Vec::with_capacity(u.members.len());
        for m in &u.members {
            let authority: Authority = m
                .address
                .parse()
                .with_context(|| format!("invalid upstream address '{}'", m.address))?;
            let scheme: Scheme = m
                .scheme
                .parse()
                .with_context(|| format!("invalid scheme '{}'", m.scheme))?;
            if scheme != Scheme::HTTP && scheme != Scheme::HTTPS {
                anyhow::bail!(
                    "upstream pool '{}': only http and https schemes are supported, got '{}'",
                    u.name,
                    m.scheme
                );
            }
            let member_label = format!("{}@{}", u.name, m.address);
            let bytes_sent = metrics::counter!(
                "quik_upstream_bytes_sent_total",
                "pool" => u.name.clone(),
                "member" => member_label.clone(),
            );
            let bytes_received = metrics::counter!(
                "quik_upstream_bytes_received_total",
                "pool" => u.name.clone(),
                "member" => member_label.clone(),
            );
            let inflight_gauge = metrics::gauge!(
                "quik_upstream_inflight",
                "pool" => u.name.clone(),
                "member" => member_label.clone(),
            );
            members.push(Upstream {
                name: member_label,
                address: m.address.clone(),
                authority,
                scheme,
                source: MemberSource::Config,
                health: Arc::new(UpstreamHealth::new(&u.health)),
                active_health: Arc::new(build_active_health(&u.active_health)),
                lifecycle: Arc::new(state::MemberLifecycle::new()),
                bytes_sent,
                bytes_received,
                inflight_gauge,
            });
        }
        let balancer: Box<dyn Balancer> = match u.balancer {
            BalancerKind::RoundRobin => Box::new(balance::RoundRobin::new()),
            BalancerKind::Random => Box::new(balance::Random::new()),
            BalancerKind::LeastConnections => Box::new(balance::LeastConnections::new()),
        };
        let client =
            build_client(u).with_context(|| format!("building client for pool '{}'", u.name))?;
        out.insert(
            u.name.clone(),
            Arc::new(UpstreamPoolEntry {
                name: u.name.clone(),
                members: ArcSwap::from(into_member_list(members)),
                balancer,
                client,
                http_version: u.http_version,
                write_lock: tokio::sync::Mutex::new(()),
                active_health_cfg: u.active_health.clone(),
                drain_cfg: u.drain.clone(),
                health_cfg: u.health.clone(),
                balancer_name: u.balancer,
                nats_cfg: u.nats.clone(),
            }),
        );
    }
    Ok(out)
}

fn build_client(u: &UpstreamPoolConfig) -> Result<ProxyClient> {
    // install_default returns Err on second call (idempotent across the process).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // ALPN is set by hyper-rustls via .enable_http1() / .enable_http2() below -
    // don't pre-populate alpn_protocols here (hyper-rustls panics if we do).
    let tls_config = if u.tls.skip_verify {
        tracing::warn!(
            pool = %u.name,
            "skip_verify is enabled - upstream TLS certificates will not be checked"
        );
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };

    let mut http = HttpConnector::new();
    http.set_nodelay(true);
    http.set_keepalive(Some(Duration::from_secs(60)));
    http.enforce_http(false); // allow https URIs

    // ALPN advertises only the protocol this pool will use, so the TLS
    // handshake never produces a connection of the "wrong" type.
    let alpn_stage = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http();
    let https = match u.http_version {
        UpstreamHttpVersion::H1 => alpn_stage.enable_http1().wrap_connector(http),
        UpstreamHttpVersion::H2 => alpn_stage.enable_http2().wrap_connector(http),
    };

    let client: ProxyClient = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(u.pool.max_idle_per_host)
        .pool_idle_timeout(Duration::from_millis(u.pool.idle_timeout_ms))
        .build(https);
    Ok(client)
}

/// Dangerous: accepts any server certificate. Only used when a pool's
/// `tls.skip_verify = true` - for internal CAs, self-signed certs in test
/// environments, or trusted private networks.
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
