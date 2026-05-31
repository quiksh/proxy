//! Admin listener — `/healthz`, `/metrics`, and the `/admin/pools` API.
//!
//! The listener runs plain HTTP by default. When any auth group is configured
//! as `mtls`, the entire listener becomes TLS — `mod.rs::serve` branches once
//! at startup between `serve_plain` and `serve_tls`. The TLS variant carries
//! the verified client cert through to the dispatch layer for audit logging.
//!
//! `MemberLifecycle`, `ActiveHealth`, drain, and probe state are surfaced
//! through `/admin/pools/*`. The auth boundary is the listener's bind address
//! plus the configured per-group mode.

pub mod api;
pub mod auth;
pub mod types;

use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ServerBuilder;
use metrics_exporter_prometheus::PrometheusHandle;
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::config::{AdminConfig, AdminTlsConfig};
use crate::shutdown::Coordinator;
use crate::upstream::Pool;

use auth::CompiledAuthGroups;

type AdminBody = BoxBody<Bytes, hyper::Error>;

/// Resources the admin listener needs at runtime. Built once at startup.
pub struct AdminState {
    pub metrics: PrometheusHandle,
    pub upstreams: Arc<Pool>,
    pub auth_groups: CompiledAuthGroups,
}

/// Build the admin auth groups from config, resolving env-var-backed
/// secrets. Call once at startup so a missing env var fails fast.
pub fn compile_auth(cfg: &AdminConfig) -> Result<CompiledAuthGroups> {
    auth::compile(&cfg.auth)
}

/// Run the admin listener. Branches at startup between plain HTTP and TLS
/// based on whether any auth group requires mTLS.
pub async fn serve(
    listener: TcpListener,
    state: AdminState,
    tls_cfg: Option<&AdminTlsConfig>,
    shutdown: Coordinator,
) -> Result<()> {
    let addr = listener.local_addr()?;

    if state.auth_groups.requires_tls() {
        let tls_cfg = tls_cfg.context(
            "admin auth requires TLS but [admin.tls] is missing — \
             this should have been caught at config validation",
        )?;
        let acceptor = build_admin_tls(tls_cfg, state.auth_groups.requires_mtls())?;
        tracing::info!(%addr, "admin listener bound (TLS, mTLS enabled)");
        serve_tls(listener, acceptor, state, shutdown).await
    } else {
        tracing::info!(%addr, "admin listener bound (plain HTTP)");
        serve_plain(listener, state, shutdown).await
    }
}

async fn serve_plain(
    listener: TcpListener,
    state: AdminState,
    shutdown: Coordinator,
) -> Result<()> {
    let state = Arc::new(state);
    loop {
        tokio::select! {
            _ = shutdown.wait_for_drain_start() => {
                tracing::info!("admin listener stopping accept");
                return Ok(());
            }
            res = listener.accept() => {
                let (stream, peer) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "admin accept failed");
                        continue;
                    }
                };
                let _ = stream.set_nodelay(true);
                let state = state.clone();
                let shutdown = shutdown.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req| {
                        let state = state.clone();
                        let shutdown = shutdown.clone();
                        async move {
                            Ok::<_, std::convert::Infallible>(
                                handle_admin(req, &state, &shutdown, peer, None).await,
                            )
                        }
                    });
                    if let Err(e) = ServerBuilder::new(TokioExecutor::new())
                        .serve_connection(io, svc)
                        .await
                    {
                        tracing::debug!(peer = %peer, error = %e, "admin conn ended");
                    }
                });
            }
        }
    }
}

async fn serve_tls(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    state: AdminState,
    shutdown: Coordinator,
) -> Result<()> {
    let state = Arc::new(state);
    loop {
        tokio::select! {
            _ = shutdown.wait_for_drain_start() => {
                tracing::info!("admin TLS listener stopping accept");
                return Ok(());
            }
            res = listener.accept() => {
                let (tcp, peer) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "admin accept failed");
                        continue;
                    }
                };
                let _ = tcp.set_nodelay(true);
                let acceptor = acceptor.clone();
                let state = state.clone();
                let shutdown = shutdown.clone();
                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(tcp).await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::info!(
                                target: "quik::admin::audit",
                                event = "admin_auth_fail",
                                reason = "tls_handshake",
                                peer = %peer,
                                error = %e,
                                "admin TLS handshake failed"
                            );
                            return;
                        }
                    };
                    // Extract the verified client cert (if any) for mTLS audit.
                    let peer_cert = {
                        let (_, conn) = tls_stream.get_ref();
                        conn.peer_certificates()
                            .and_then(|c| c.first())
                            .map(|c| c.clone().into_owned())
                    };
                    let io = TokioIo::new(tls_stream);
                    let svc = service_fn(move |req| {
                        let state = state.clone();
                        let shutdown = shutdown.clone();
                        let peer_cert = peer_cert.clone();
                        async move {
                            Ok::<_, std::convert::Infallible>(
                                handle_admin(req, &state, &shutdown, peer, peer_cert).await,
                            )
                        }
                    });
                    if let Err(e) = ServerBuilder::new(TokioExecutor::new())
                        .serve_connection(io, svc)
                        .await
                    {
                        tracing::debug!(peer = %peer, error = %e, "admin conn ended");
                    }
                });
            }
        }
    }
}

/// Build a rustls ServerConfig for the admin listener. If `require_client_cert`
/// is true, the configured `client_ca_path` becomes the trust root for the
/// `WebPkiClientVerifier`.
fn build_admin_tls(cfg: &AdminTlsConfig, require_client_cert: bool) -> Result<TlsAcceptor> {
    // Crypto provider — same lazy install pattern as the inbound listener.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cert_pem = std::fs::read(&cfg.cert_path)
        .with_context(|| format!("reading admin cert {}", cfg.cert_path.display()))?;
    let key_pem = std::fs::read(&cfg.key_path)
        .with_context(|| format!("reading admin key {}", cfg.key_path.display()))?;
    let certs = parse_certs(&cert_pem)?;
    let key = parse_key(&key_pem)?;

    let builder = ServerConfig::builder();

    let server_config = if require_client_cert {
        let ca_path = cfg
            .client_ca_path
            .as_ref()
            .context("admin TLS with mTLS auth requires client_ca_path in [admin.tls]")?;
        let ca_pem = std::fs::read(ca_path)
            .with_context(|| format!("reading admin client CA {}", ca_path.display()))?;
        let ca_certs = parse_certs(&ca_pem)?;
        let mut roots = rustls::RootCertStore::empty();
        for c in ca_certs {
            roots
                .add(c)
                .context("adding admin client CA cert to root store")?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .context("building admin client cert verifier")?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .context("building admin rustls ServerConfig with mTLS")?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("building admin rustls ServerConfig")?
    };

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

fn parse_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = std::io::BufReader::new(pem);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.context("parsing admin certificate PEM")?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in admin PEM");
    }
    Ok(certs)
}

fn parse_key(pem: &[u8]) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let mut reader = std::io::BufReader::new(pem);
    rustls_pemfile::private_key(&mut reader)
        .context("parsing admin private key PEM")?
        .context("no private key found in admin PEM")
}

async fn handle_admin(
    req: Request<Incoming>,
    state: &Arc<AdminState>,
    shutdown: &Coordinator,
    peer: std::net::SocketAddr,
    peer_cert: Option<CertificateDer<'static>>,
) -> Response<AdminBody> {
    let path = req.uri().path();

    // Unauthenticated read endpoints — open by design.
    match (req.method(), path) {
        (&Method::GET, "/healthz") | (&Method::GET, "/health") => {
            return if shutdown.is_draining() {
                plain_response(StatusCode::SERVICE_UNAVAILABLE, "draining\n")
            } else {
                plain_response(StatusCode::OK, "ok\n")
            };
        }
        (&Method::GET, "/metrics") => {
            return plain_response(StatusCode::OK, stable_metrics(&state.metrics.render()));
        }
        _ => {}
    }

    // /admin/* endpoints — auth-gated.
    if path.starts_with("/admin/") {
        let req_state = api::RequestState {
            upstreams: &state.upstreams,
            auth_groups: &state.auth_groups,
            shutdown,
            peer,
            peer_cert,
        };
        return api::dispatch(req, req_state).await;
    }

    plain_response(StatusCode::NOT_FOUND, "not found\n")
}

/// Sort the data lines within each metric block so the output is byte-stable
/// across scrapes. Prometheus scrapers don't care about order — but a human
/// curl'ing `/metrics` repeatedly does, because random reshuffling makes
/// diffs unreadable.
fn stable_metrics(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut header_lines: Vec<&str> = Vec::new();
    let mut data_lines: Vec<&str> = Vec::new();

    let flush = |out: &mut String, headers: &mut Vec<&str>, data: &mut Vec<&str>| {
        for h in headers.drain(..) {
            out.push_str(h);
            out.push('\n');
        }
        data.sort_unstable();
        for d in data.drain(..) {
            out.push_str(d);
            out.push('\n');
        }
    };

    for line in text.lines() {
        if line.is_empty() {
            flush(&mut out, &mut header_lines, &mut data_lines);
            out.push('\n');
        } else if line.starts_with('#') {
            header_lines.push(line);
        } else {
            data_lines.push(line);
        }
    }
    flush(&mut out, &mut header_lines, &mut data_lines);
    out
}

fn plain_response(status: StatusCode, body: impl Into<Bytes>) -> Response<AdminBody> {
    let body = Full::new(body.into())
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body)
        .expect("static response builds")
}
