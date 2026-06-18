//! Shared test harness: cert generation, test backend, proxy spawning.
//!
//! Each integration-test binary uses a subset of this module - items it doesn't
//! reference are otherwise flagged as dead code. Suppress at the module level.
#![allow(dead_code)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use futures::stream;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use http_body::Frame;
use http_body_util::{BodyExt, Empty, Full, StreamBody, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperServer;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use quik::config::{
    AdminConfig, AuthBlockConfig, BalancerKind, Config, ListenerConfig, LogFormat, LoggingConfig,
    Mode, RouteConfig, ShutdownConfig, TlsConfig, UpstreamHealthConfig, UpstreamHttpVersion,
    UpstreamMember, UpstreamPoolConfig, UpstreamTlsConfig,
};
use quik::routing::SharedRoutingTable;
use quik::shutdown::Coordinator;
use quik::upstream::Pool;

#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: Method,
    pub path: String,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub version: http::Version,
}

pub struct Backend {
    pub addr: SocketAddr,
    pub name: String,
    pub recorder: Arc<Mutex<Vec<RecordedRequest>>>,
    /// Active-health probes hit `/healthz`. Tests flip this status to drive
    /// the probe state machine (200 → healthy, 503 → unhealthy). Initial 200.
    pub healthz_status: Arc<AtomicU16>,
    /// Counter of probe hits to `/healthz`. Lets tests assert "the probe
    /// task hit me at least N times".
    pub healthz_count: Arc<AtomicU32>,
    _task: JoinHandle<()>,
}

impl Backend {
    /// Set the status returned on `/healthz`. Used by active-health tests to
    /// flip a member between healthy and unhealthy.
    pub fn set_healthz_status(&self, status: u16) {
        self.healthz_status.store(status, Ordering::Relaxed);
    }

    /// Number of probe hits seen so far.
    pub fn healthz_count(&self) -> u32 {
        self.healthz_count.load(Ordering::Relaxed)
    }
}

impl Backend {
    pub async fn spawn(name: impl Into<String>) -> Self {
        Self::spawn_full(name, StatusCode::OK, Duration::ZERO).await
    }

    pub async fn spawn_with_status(name: impl Into<String>, status: StatusCode) -> Self {
        Self::spawn_full(name, status, Duration::ZERO).await
    }

    pub async fn spawn_with_delay(name: impl Into<String>, delay: Duration) -> Self {
        Self::spawn_full(name, StatusCode::OK, delay).await
    }

    /// Spawn a backend whose response status can be mutated at runtime. Tests
    /// use this to drive the passive-health state machine - flip to 503,
    /// observe ejection, flip back to 200, observe recovery.
    pub async fn spawn_with_dynamic_status(name: impl Into<String>) -> (Self, Arc<AtomicU16>) {
        let name = name.into();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let addr = listener.local_addr().expect("local_addr");
        let recorder: Arc<Mutex<Vec<RecordedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let status = Arc::new(AtomicU16::new(200));
        let healthz_status = Arc::new(AtomicU16::new(200));
        let healthz_count = Arc::new(AtomicU32::new(0));

        let rec = recorder.clone();
        let backend_name = name.clone();
        let status_for_task = status.clone();
        let hz_status = healthz_status.clone();
        let hz_count = healthz_count.clone();
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let rec = rec.clone();
                let backend_name = backend_name.clone();
                let status_h = status_for_task.clone();
                let hz_status = hz_status.clone();
                let hz_count = hz_count.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let rec = rec.clone();
                        let backend_name = backend_name.clone();
                        let hz_status = hz_status.clone();
                        let hz_count = hz_count.clone();
                        let s = StatusCode::from_u16(status_h.load(Ordering::Relaxed))
                            .unwrap_or(StatusCode::OK);
                        async move {
                            Ok::<_, Infallible>(
                                handle_backend_request(
                                    req,
                                    &backend_name,
                                    s,
                                    rec,
                                    hz_status,
                                    hz_count,
                                )
                                .await,
                            )
                        }
                    });
                    let _ = HyperServer::new(TokioExecutor::new())
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });

        (
            Self {
                addr,
                name,
                recorder,
                healthz_status,
                healthz_count,
                _task: task,
            },
            status,
        )
    }

    async fn spawn_full(name: impl Into<String>, status: StatusCode, delay: Duration) -> Self {
        let name = name.into();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let addr = listener.local_addr().expect("local_addr");
        let recorder: Arc<Mutex<Vec<RecordedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let healthz_status = Arc::new(AtomicU16::new(200));
        let healthz_count = Arc::new(AtomicU32::new(0));

        let rec = recorder.clone();
        let backend_name = name.clone();
        let hz_status = healthz_status.clone();
        let hz_count = healthz_count.clone();
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let rec = rec.clone();
                let backend_name = backend_name.clone();
                let hz_status = hz_status.clone();
                let hz_count = hz_count.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let rec = rec.clone();
                        let backend_name = backend_name.clone();
                        let hz_status = hz_status.clone();
                        let hz_count = hz_count.clone();
                        async move {
                            if !delay.is_zero() {
                                tokio::time::sleep(delay).await;
                            }
                            Ok::<_, Infallible>(
                                handle_backend_request(
                                    req,
                                    &backend_name,
                                    status,
                                    rec,
                                    hz_status,
                                    hz_count,
                                )
                                .await,
                            )
                        }
                    });
                    let _ = HyperServer::new(TokioExecutor::new())
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });

        Self {
            addr,
            name,
            recorder,
            healthz_status,
            healthz_count,
            _task: task,
        }
    }

    /// Spawn a plain-HTTP WebSocket echo backend. Uses tokio-tungstenite to
    /// do the handshake + echo received frames. The proxy terminates TLS from
    /// the client, then upgrades over plain HTTP to this backend (the common
    /// production pattern for east-west traffic).
    pub async fn spawn_ws_echo(name: impl Into<String>) -> Self {
        let name = name.into();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ws backend");
        let addr = listener.local_addr().expect("local_addr");
        let recorder: Arc<Mutex<Vec<RecordedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        // WS backend doesn't actually serve /healthz, but the struct shape
        // requires the fields; tests don't read them for this variant.
        let healthz_status = Arc::new(AtomicU16::new(200));
        let healthz_count = Arc::new(AtomicU32::new(0));

        let task = tokio::spawn(async move {
            loop {
                let (tcp, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut ws = match tokio_tungstenite::accept_async(tcp).await {
                        Ok(ws) => ws,
                        Err(_) => return,
                    };
                    use futures::{SinkExt, StreamExt};
                    while let Some(Ok(msg)) = ws.next().await {
                        if msg.is_close() {
                            return;
                        }
                        if ws.send(msg).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });

        Self {
            addr,
            name,
            recorder,
            healthz_status,
            healthz_count,
            _task: task,
        }
    }

    /// Spawn an SSE-streaming backend. On every request the backend writes
    /// `num_events` text/event-stream events, sleeping `interval` between
    /// each. Used to verify the proxy doesn't buffer streaming bodies.
    pub async fn spawn_sse(name: impl Into<String>, num_events: u32, interval: Duration) -> Self {
        let name = name.into();
        let cert = gen_cert();
        let tls_acceptor = quik::tls::build_acceptor_from_pem(&cert.cert_pem, &cert.key_pem)
            .expect("backend tls acceptor");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind sse backend");
        let healthz_status = Arc::new(AtomicU16::new(200));
        let healthz_count = Arc::new(AtomicU32::new(0));
        let addr = listener.local_addr().expect("local_addr");
        let recorder: Arc<Mutex<Vec<RecordedRequest>>> = Arc::new(Mutex::new(Vec::new()));

        let rec = recorder.clone();
        let bname = name.clone();
        let task = tokio::spawn(async move {
            loop {
                let (tcp, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let rec = rec.clone();
                let bname = bname.clone();
                let tls = tls_acceptor.clone();
                tokio::spawn(async move {
                    let tls_stream = match tls.accept(tcp).await {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    let io = TokioIo::new(tls_stream);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let rec = rec.clone();
                        let bname = bname.clone();
                        async move {
                            Ok::<_, Infallible>(
                                handle_sse_request(req, &bname, num_events, interval, rec).await,
                            )
                        }
                    });
                    let _ = HyperServer::new(TokioExecutor::new())
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });

        Self {
            addr,
            name,
            recorder,
            healthz_status,
            healthz_count,
            _task: task,
        }
    }

    /// Spawn a TLS-terminating echo backend. Self-signed cert is generated
    /// at spawn time. ALPN advertises both h2 and http/1.1.
    pub async fn spawn_https(name: impl Into<String>) -> Self {
        let name = name.into();
        let cert = gen_cert();
        let tls_acceptor = quik::tls::build_acceptor_from_pem(&cert.cert_pem, &cert.key_pem)
            .expect("backend tls acceptor");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind tls backend");
        let addr = listener.local_addr().expect("local_addr");
        let recorder: Arc<Mutex<Vec<RecordedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let healthz_status = Arc::new(AtomicU16::new(200));
        let healthz_count = Arc::new(AtomicU32::new(0));

        let rec = recorder.clone();
        let backend_name = name.clone();
        let hz_status = healthz_status.clone();
        let hz_count = healthz_count.clone();
        let task = tokio::spawn(async move {
            loop {
                let (tcp, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let rec = rec.clone();
                let backend_name = backend_name.clone();
                let tls_acceptor = tls_acceptor.clone();
                let hz_status = hz_status.clone();
                let hz_count = hz_count.clone();
                tokio::spawn(async move {
                    let tls_stream = match tls_acceptor.accept(tcp).await {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    let io = TokioIo::new(tls_stream);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let rec = rec.clone();
                        let backend_name = backend_name.clone();
                        let hz_status = hz_status.clone();
                        let hz_count = hz_count.clone();
                        async move {
                            Ok::<_, Infallible>(
                                handle_backend_request(
                                    req,
                                    &backend_name,
                                    StatusCode::OK,
                                    rec,
                                    hz_status,
                                    hz_count,
                                )
                                .await,
                            )
                        }
                    });
                    let _ = HyperServer::new(TokioExecutor::new())
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });

        Self {
            addr,
            name,
            recorder,
            healthz_status,
            healthz_count,
            _task: task,
        }
    }

    pub fn calls(&self) -> Vec<RecordedRequest> {
        self.recorder.lock().unwrap().clone()
    }
}

async fn handle_backend_request(
    req: Request<Incoming>,
    name: &str,
    status: StatusCode,
    recorder: Arc<Mutex<Vec<RecordedRequest>>>,
    healthz_status: Arc<AtomicU16>,
    healthz_count: Arc<AtomicU32>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();

    // Probe path is handled separately so `recorder` only sees real traffic;
    // tests assert on it without filtering out healthz noise.
    if parts.uri.path() == "/healthz" {
        healthz_count.fetch_add(1, Ordering::Relaxed);
        let s =
            StatusCode::from_u16(healthz_status.load(Ordering::Relaxed)).unwrap_or(StatusCode::OK);
        let body = Full::new(Bytes::from_static(b"ok"))
            .map_err(|never| match never {})
            .boxed();
        return Response::builder()
            .status(s)
            .header("content-type", "text/plain")
            .body(body)
            .unwrap();
    }

    recorder.lock().unwrap().push(RecordedRequest {
        method: parts.method.clone(),
        path: parts.uri.path().to_string(),
        headers: parts.headers.clone(),
        body: body.clone(),
        version: parts.version,
    });

    let payload = format!(
        r#"{{"backend":"{name}","echoed_path":"{}","echoed_method":"{}","echoed_body_bytes":{}}}"#,
        parts.uri.path(),
        parts.method,
        body.len()
    );

    // If the inbound request asked for trailers via x-want-trailers, parse the
    // comma-separated "name=value" pairs and emit them as response trailers
    // after the data frame. Used by the gRPC trailer round-trip test.
    let trailers = parts
        .headers
        .get("x-want-trailers")
        .and_then(|h| h.to_str().ok())
        .map(|s| {
            let mut hm = HeaderMap::new();
            for pair in s.split(',') {
                if let Some((k, v)) = pair.split_once('=')
                    && let (Ok(name), Ok(val)) = (
                        HeaderName::try_from(k.trim()),
                        HeaderValue::try_from(v.trim()),
                    )
                {
                    hm.insert(name, val);
                }
            }
            hm
        });

    let body: BoxBody<Bytes, hyper::Error> = if let Some(t) = trailers {
        let frames = stream::iter(vec![
            Ok::<_, hyper::Error>(Frame::data(Bytes::from(payload))),
            Ok::<_, hyper::Error>(Frame::trailers(t)),
        ]);
        StreamBody::new(frames).boxed()
    } else {
        Full::new(Bytes::from(payload))
            .map_err(|never| match never {})
            .boxed()
    };

    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("x-backend-name", name)
        .body(body)
        .unwrap()
}

pub struct TestCert {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

pub fn gen_cert() -> TestCert {
    let params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("rcgen params");
    let key_pair = rcgen::KeyPair::generate().expect("rcgen keypair");
    let cert = params.self_signed(&key_pair).expect("rcgen sign");
    TestCert {
        cert_pem: cert.pem().into_bytes(),
        key_pem: key_pair.serialize_pem().into_bytes(),
    }
}

pub struct ProxyHandle {
    pub addr: SocketAddr,
    pub admin_addr: SocketAddr,
    pub shutdown: Coordinator,
    _proxy_task: JoinHandle<anyhow::Result<()>>,
    _admin_task: JoinHandle<anyhow::Result<()>>,
}

pub struct ProxySpec {
    pub pools: Vec<Backends>,
    pub routes: Vec<RouteConfig>,
}

pub struct Backends {
    pub name: String,
    pub members: Vec<(SocketAddr, &'static str)>,
    pub skip_verify: bool,
    pub balancer: BalancerKind,
    pub health: UpstreamHealthConfig,
    pub http_version: UpstreamHttpVersion,
    /// Active health (default: disabled).
    pub active_health: quik::config::ActiveHealthConfig,
    /// Drain timeout (default: 60s - but tests usually want shorter).
    pub drain: quik::config::DrainConfig,
    /// NATS registration binding (default: none). Set via [`Backends::with_nats`].
    pub nats: Option<quik::config::UpstreamNatsConfig>,
}

impl Backends {
    pub fn http(name: impl Into<String>, addrs: Vec<SocketAddr>) -> Self {
        Self {
            name: name.into(),
            members: addrs.into_iter().map(|a| (a, "http")).collect(),
            skip_verify: false,
            balancer: BalancerKind::RoundRobin,
            health: UpstreamHealthConfig::default(),
            http_version: UpstreamHttpVersion::H1,
            active_health: Default::default(),
            drain: Default::default(),
            nats: None,
        }
    }

    pub fn https_skip_verify(name: impl Into<String>, addrs: Vec<SocketAddr>) -> Self {
        Self {
            name: name.into(),
            members: addrs.into_iter().map(|a| (a, "https")).collect(),
            skip_verify: true,
            balancer: BalancerKind::RoundRobin,
            health: UpstreamHealthConfig::default(),
            http_version: UpstreamHttpVersion::H1,
            active_health: Default::default(),
            drain: Default::default(),
            nats: None,
        }
    }

    /// Configure active health checks for this pool.
    pub fn with_active_health(mut self, ah: quik::config::ActiveHealthConfig) -> Self {
        self.active_health = ah;
        self
    }

    /// Override drain timeout. Tests usually use 1-3 seconds.
    pub fn with_drain_timeout_ms(mut self, ms: u64) -> Self {
        self.drain = quik::config::DrainConfig { timeout_ms: ms };
        self
    }

    /// Make this pool NATS-backed (used by the e2e_nats integration tests).
    pub fn with_nats(mut self, nats: quik::config::UpstreamNatsConfig) -> Self {
        self.nats = Some(nats);
        self
    }

    /// Switch the LB algorithm. Used by passive-health and LC tests.
    pub fn with_balancer(mut self, b: BalancerKind) -> Self {
        self.balancer = b;
        self
    }

    /// Override health tuning so tests can use small thresholds + windows.
    pub fn with_health(mut self, h: UpstreamHealthConfig) -> Self {
        self.health = h;
        self
    }

    /// Switch the upstream HTTP version. Default H1; H2 is needed for the
    /// h2-end-to-end and gRPC-trailer tests.
    pub fn with_http_version(mut self, v: UpstreamHttpVersion) -> Self {
        self.http_version = v;
        self
    }
}

/// Convenience constructor for a simple prefix-matched route.
pub fn route(path_prefix: &str, upstream: &str) -> RouteConfig {
    RouteConfig {
        path_prefix: Some(path_prefix.to_string()),
        upstream: upstream.to_string(),
        ..Default::default()
    }
}

pub async fn spawn_proxy(spec: ProxySpec) -> ProxyHandle {
    spawn_proxy_full(
        spec,
        Mode::Edge,
        vec![],
        None,
        None,
        None,
        Default::default(),
    )
    .await
}

pub async fn spawn_proxy_with_mode(spec: ProxySpec, mode: Mode) -> ProxyHandle {
    spawn_proxy_full(spec, mode, vec![], None, None, None, Default::default()).await
}

/// Spawn a proxy with a `[forwarded]` policy (trusted proxies / RFC 7239
/// emit). Used by the forwarding-header e2e tests.
pub async fn spawn_proxy_with_forwarded(
    spec: ProxySpec,
    mode: Mode,
    forwarded: quik::config::ForwardedConfig,
) -> ProxyHandle {
    spawn_proxy_full(spec, mode, vec![], None, None, None, forwarded).await
}

/// Spawn a proxy with overridden listener limits. Used by the hardening
/// tests to exercise tighter-than-default timeouts and WS idle culling.
pub async fn spawn_proxy_with_limits(
    spec: ProxySpec,
    limits: quik::config::ListenerLimitsConfig,
) -> ProxyHandle {
    spawn_proxy_full(
        spec,
        Mode::Edge,
        vec![],
        None,
        Some(limits),
        None,
        Default::default(),
    )
    .await
}

pub async fn spawn_proxy_with_auth(
    spec: ProxySpec,
    auth_blocks: Vec<AuthBlockConfig>,
) -> ProxyHandle {
    spawn_proxy_full(
        spec,
        Mode::Edge,
        auth_blocks,
        None,
        None,
        None,
        Default::default(),
    )
    .await
}

/// Spawn a proxy with admin auth configured. Used by the admin-auth e2e
/// tests. When `admin_auth` is the default the listener stays open.
pub async fn spawn_proxy_with_admin_auth(
    spec: ProxySpec,
    admin_auth: quik::config::AdminAuthGroups,
) -> ProxyHandle {
    spawn_proxy_full(
        spec,
        Mode::Edge,
        vec![],
        Some(admin_auth),
        None,
        None,
        Default::default(),
    )
    .await
}

/// Spawn a proxy with a top-level `[nats]` config - used by the e2e_nats tests.
/// The watcher is only spawned in a `--features nats` build.
pub async fn spawn_proxy_with_nats(spec: ProxySpec, nats: quik::config::NatsConfig) -> ProxyHandle {
    spawn_proxy_full(
        spec,
        Mode::Edge,
        vec![],
        None,
        None,
        Some(nats),
        Default::default(),
    )
    .await
}

async fn spawn_proxy_full(
    spec: ProxySpec,
    mode: Mode,
    auth_blocks: Vec<AuthBlockConfig>,
    admin_auth: Option<quik::config::AdminAuthGroups>,
    limits: Option<quik::config::ListenerLimitsConfig>,
    nats: Option<quik::config::NatsConfig>,
    forwarded: quik::config::ForwardedConfig,
) -> ProxyHandle {
    let cert = gen_cert();

    let upstreams: Vec<UpstreamPoolConfig> = spec
        .pools
        .into_iter()
        .map(|p| UpstreamPoolConfig {
            name: p.name,
            members: p
                .members
                .into_iter()
                .map(|(addr, scheme)| UpstreamMember {
                    address: addr.to_string(),
                    scheme: scheme.to_string(),
                })
                .collect(),
            balancer: p.balancer,
            tls: UpstreamTlsConfig {
                skip_verify: p.skip_verify,
            },
            health: p.health,
            http_version: p.http_version,
            active_health: p.active_health,
            drain: p.drain,
            pool: Default::default(),
            nats: p.nats,
        })
        .collect();

    let routes: Vec<RouteConfig> = spec.routes;
    let limits = limits.unwrap_or_default();

    let cfg = Config {
        mode,
        forwarded,
        listener: ListenerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            tls: TlsConfig {
                cert_path: "ignored".into(),
                key_path: "ignored".into(),
            },
            limits,
        },
        admin: AdminConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            auth: admin_auth.unwrap_or_default(),
        },
        shutdown: ShutdownConfig {
            drain_grace_seconds: 3,
            pre_drain_grace_seconds: 0,
        },
        logging: LoggingConfig {
            level: "warn".to_string(),
            format: LogFormat::Json,
            client_ip_header: None,
            user_agent: false,
        },
        upstreams,
        routes,
        auth: auth_blocks,
        egress: None,
        nats,
    };

    // IMPORTANT: install the prometheus recorder BEFORE building the pool -
    // each Upstream pre-builds metrics::Counter / Gauge handles in its
    // constructor, and those handles bind to whatever recorder is global at
    // construction time. If we built the pool first, the handles would
    // point at the no-op recorder and the counters would silently stay 0.
    let metrics = shared_metrics_handle();

    let routing = Arc::new(SharedRoutingTable::from_config(&cfg).expect("routing"));
    let tls = quik::tls::build_acceptor_from_pem(&cert.cert_pem, &cert.key_pem).expect("tls");

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let admin_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind admin");
    let addr = proxy_listener.local_addr().unwrap();
    let admin_addr = admin_listener.local_addr().unwrap();

    let shutdown = Coordinator::new(
        cfg.shutdown.drain_grace_seconds,
        cfg.shutdown.pre_drain_grace_seconds,
    );

    // Build the auth registry. For tests we use the skip_verify JWKS client
    // so the harness's self-signed-or-plaintext JWKS server is reachable.
    let auth_registry = if cfg.auth.is_empty() {
        Arc::new(quik::auth::AuthRegistry::empty())
    } else {
        Arc::new(quik::auth::AuthRegistry::from_config_for_tests(&cfg).expect("auth"))
    };

    let upstreams = Arc::new(Pool::from_config(&cfg).expect("pool"));

    // Mirror main.rs: spawn a probe task for any pool with active_health.
    // Tests that don't enable active_health get nothing spawned.
    for entry in upstreams.snapshot().values() {
        if entry.active_health_cfg.enabled {
            tokio::spawn(quik::upstream::probe::run_pool_probes(
                entry.clone(),
                shutdown.clone(),
            ));
        }
    }

    // Mirror main.rs: the NATS watcher (only in a `--features nats` build).
    #[cfg(feature = "nats")]
    if let Some(nats_cfg) = cfg.nats.clone() {
        tokio::spawn(quik::upstream::nats::run_watcher(
            upstreams.clone(),
            nats_cfg,
            shutdown.clone(),
        ));
    }

    // Admin auth is None/None for tests by default - e2e tests for auth
    // build their own ProxyHandle with explicit config.
    let admin_auth = quik::admin::compile_auth(&cfg.admin).expect("admin auth compile");
    let admin_state = quik::admin::AdminState {
        metrics,
        upstreams: upstreams.clone(),
        auth_groups: admin_auth,
    };
    let admin_tls_cfg = cfg.admin.tls.clone();
    let shutdown_for_admin = shutdown.clone();
    let admin_task = tokio::spawn(async move {
        quik::admin::serve(
            admin_listener,
            admin_state,
            admin_tls_cfg.as_ref(),
            shutdown_for_admin,
        )
        .await
    });

    let proxy_task = tokio::spawn(quik::proxy::serve(
        proxy_listener,
        tls,
        quik::proxy::ServerState {
            routing,
            upstreams: upstreams.clone(),
            auth: auth_registry,
            mode: cfg.mode,
            forwarded: std::sync::Arc::new(quik::headers::ForwardedPolicy::from_config(
                &cfg.forwarded,
            )),
            access: std::sync::Arc::new(
                quik::proxy::AccessLogFields::from_logging(&cfg.logging)
                    .expect("valid logging config"),
            ),
            limits: std::sync::Arc::new(cfg.listener.limits.clone()),
        },
        shutdown.clone(),
    ));

    ProxyHandle {
        addr,
        admin_addr,
        shutdown,
        _proxy_task: proxy_task,
        _admin_task: admin_task,
    }
}

/// Install the shared recorder. Used by tests that don't construct a full
/// proxy harness but still need metric handles (e.g. the egress tests).
pub fn install_metrics_recorder() {
    let _ = shared_metrics_handle();
}

/// Install the prometheus recorder exactly once per test process. Cargo runs
/// the tests inside a binary on multiple threads in parallel, so calling
/// `install_recorder()` per test would fail after the first.
fn shared_metrics_handle() -> metrics_exporter_prometheus::PrometheusHandle {
    static HANDLE: OnceLock<metrics_exporter_prometheus::PrometheusHandle> = OnceLock::new();
    HANDLE
        .get_or_init(|| {
            metrics_exporter_prometheus::PrometheusBuilder::new()
                .install_recorder()
                .expect("install prometheus recorder in test harness")
        })
        .clone()
}

async fn handle_sse_request(
    req: Request<Incoming>,
    name: &str,
    num_events: u32,
    interval: Duration,
    recorder: Arc<Mutex<Vec<RecordedRequest>>>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    recorder.lock().unwrap().push(RecordedRequest {
        method: parts.method.clone(),
        path: parts.uri.path().to_string(),
        headers: parts.headers.clone(),
        body,
        version: parts.version,
    });

    let frames = stream::unfold(0u32, move |i| async move {
        if i >= num_events {
            return None;
        }
        if i > 0 {
            tokio::time::sleep(interval).await;
        }
        let payload = format!("event: tick\ndata: {{\"n\":{i}}}\n\n");
        let frame = Ok::<_, hyper::Error>(Frame::data(Bytes::from(payload)));
        Some((frame, i + 1))
    });
    let body = StreamBody::new(frames).boxed();

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .header("x-backend-name", name)
        .body(body)
        .unwrap()
}

/// hyper-util client that accepts self-signed certs and speaks h2 (over TLS,
/// negotiated via ALPN). Used by tests that need trailer access - reqwest's
/// public API doesn't expose response trailers.
pub fn hyper_h2_client() -> Client<hyper_rustls::HttpsConnector<HttpConnector>, Empty<Bytes>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TestNoVerifier))
        .with_no_client_auth();

    let mut http = HttpConnector::new();
    http.enforce_http(false);

    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);

    Client::builder(TokioExecutor::new()).build(https)
}

#[derive(Debug)]
struct TestNoVerifier;

impl ServerCertVerifier for TestNoVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ── JWT test fixtures ────────────────────────────────────────────────────────

/// Test JWT signer using Ed25519 (smallest keys, simplest JWK). Generates a
/// fresh keypair on construction so tests can't accidentally share keys.
pub struct TestJwtSigner {
    pub kid: String,
    pub encoding_key: jsonwebtoken::EncodingKey,
    /// 32-byte raw Ed25519 public key (already base64url-encoded for inclusion
    /// in the JWK).
    pub jwk_x_b64url: String,
}

impl TestJwtSigner {
    pub fn new() -> Self {
        Self::with_kid("test-key")
    }

    pub fn with_kid(kid: impl Into<String>) -> Self {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair");
        let private_pem = kp.serialize_pem();
        // SubjectPublicKeyInfo DER for Ed25519 is 44 bytes; the raw public key
        // is the trailing 32 bytes.
        let der = kp.public_key_der();
        let pub_bytes = &der[der.len() - 32..];
        let encoding_key = jsonwebtoken::EncodingKey::from_ed_pem(private_pem.as_bytes())
            .expect("ed25519 encoding key");
        Self {
            kid: kid.into(),
            encoding_key,
            jwk_x_b64url: URL_SAFE_NO_PAD.encode(pub_bytes),
        }
    }

    pub fn sign(&self, claims: serde_json::Value) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&header, &claims, &self.encoding_key).expect("sign jwt")
    }

    pub fn jwk(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "alg": "EdDSA",
            "kid": self.kid,
            "x": self.jwk_x_b64url,
        })
    }

    pub fn jwks_json(&self) -> String {
        serde_json::json!({"keys": [self.jwk()]}).to_string()
    }
}

/// Spawn a tiny plain-HTTP JWKS server. Returns the bound address and a handle
/// to a `Arc<Mutex<String>>` you can write to between requests to simulate
/// rotation.
pub fn spawn_jwks_server(initial: String) -> (SocketAddr, Arc<Mutex<String>>) {
    let body = Arc::new(Mutex::new(initial));
    let body_clone = body.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind jwks");
    let addr = listener.local_addr().expect("local_addr");
    listener.set_nonblocking(true).unwrap();
    let listener = TcpListener::from_std(listener).unwrap();

    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            let body = body_clone.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(tcp);
                let svc = service_fn(move |_req: Request<Incoming>| {
                    let body = body.clone();
                    async move {
                        let json = body.lock().unwrap().clone();
                        let resp = Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(json)))
                            .unwrap();
                        Ok::<_, Infallible>(resp)
                    }
                });
                let _ = HyperServer::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    (addr, body)
}

pub fn https_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client")
}

pub fn https_client_http1_only() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http1_only()
        .build()
        .expect("client")
}
