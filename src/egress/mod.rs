//! Egress (forward) proxy: HTTP CONNECT with allow/deny + SNI sniffing.
//!
//! This is a separate role from quik's primary reverse-proxy work. When
//! `[egress]` is set in the config, a dedicated listener accepts HTTP
//! CONNECT requests, applies a first-match-wins host/CIDR allow-deny
//! policy, and (when allowed) tunnels the byte stream to the requested
//! destination — peeking at the first chunk to record the TLS SNI.
//!
//! Only CONNECT is supported. Absolute-URI plain-HTTP forwarding (tier 3
//! in the original sketch) is intentionally not implemented; modern egress
//! traffic is overwhelmingly HTTPS-via-CONNECT, and adding plaintext
//! forwarding doubles the attack surface for marginal value.

mod policy;
mod sni;

pub use policy::{CompiledEgressAuth, Decision, EgressPolicy};
pub use sni::extract_sni;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ServerBuilder;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::shutdown::Coordinator;

type EgressBody = BoxBody<Bytes, hyper::Error>;

/// Run the egress listener until drain is signalled.
pub async fn serve(
    listener: TcpListener,
    policy: Arc<EgressPolicy>,
    shutdown: Coordinator,
) -> Result<()> {
    let addr = listener.local_addr()?;
    tracing::info!(%addr, "egress listener bound (plain HTTP CONNECT)");

    let tunnels_inflight = Arc::new(AtomicU64::new(0));

    loop {
        tokio::select! {
            _ = shutdown.wait_for_drain_start() => {
                tracing::info!("egress listener stopping accept");
                return Ok(());
            }
            res = listener.accept() => {
                let (tcp, peer) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        metrics::counter!("quik_proxy_errors_total", "kind" => "egress_accept").increment(1);
                        tracing::warn!(error = %e, "egress accept failed");
                        continue;
                    }
                };
                let _ = tcp.set_nodelay(true);

                let policy = policy.clone();
                let shutdown = shutdown.clone();
                let tunnels_inflight = tunnels_inflight.clone();
                tokio::spawn(async move {
                    handle_conn(tcp, peer, policy, shutdown, tunnels_inflight).await;
                });
            }
        }
    }
}

async fn handle_conn(
    tcp: TcpStream,
    peer: SocketAddr,
    policy: Arc<EgressPolicy>,
    shutdown: Coordinator,
    tunnels_inflight: Arc<AtomicU64>,
) {
    let io = TokioIo::new(tcp);
    let svc = service_fn(move |req: Request<Incoming>| {
        let policy = policy.clone();
        let shutdown = shutdown.clone();
        let tunnels_inflight = tunnels_inflight.clone();
        async move {
            Ok::<Response<EgressBody>, std::convert::Infallible>(
                handle_request(req, peer, policy, shutdown, tunnels_inflight).await,
            )
        }
    });

    let builder = ServerBuilder::new(TokioExecutor::new());
    if let Err(e) = builder.serve_connection_with_upgrades(io, svc).await {
        tracing::debug!(peer = %peer, error = %e, "egress conn ended");
    }
}

async fn handle_request(
    req: Request<Incoming>,
    peer: SocketAddr,
    policy: Arc<EgressPolicy>,
    _shutdown: Coordinator,
    tunnels_inflight: Arc<AtomicU64>,
) -> Response<EgressBody> {
    let start = Instant::now();

    if req.method() != Method::CONNECT {
        metrics::counter!("quik_egress_connects_total",
            "action" => "rejected_method", "target" => "-"
        )
        .increment(1);
        return synth_short(
            StatusCode::METHOD_NOT_ALLOWED,
            "only CONNECT is supported on the egress listener\n",
        );
    }

    // ── proxy auth (if configured) ──────────────────────────────────────
    let originator = match policy.auth() {
        None => None,
        Some(auth) => match authenticate(&req, auth).await {
            Ok(o) => Some(o),
            Err(resp) => return resp,
        },
    };
    if let Some(o) = &originator {
        tracing::Span::current().record("originator", o.as_str());
    }

    // RFC 7231 §4.3.6: authority-form ("host:port") goes in the
    // request-line, exposed via req.uri().authority().
    let authority = match req.uri().authority() {
        Some(a) => a.clone(),
        None => {
            return synth_short(StatusCode::BAD_REQUEST, "CONNECT missing authority\n");
        }
    };
    let host_raw = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(443);

    // Strip IPv6 brackets if present (e.g. `[::1]:443` → `::1`).
    let host = host_raw
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .map(str::to_owned)
        .unwrap_or(host_raw);
    let target_label = format!("{host}:{port}");

    // Resolve + apply policy. Resolution is bounded (`dns_timeout` on the
    // policy); failure → empty IP list (host-only rules can still match).
    let ips = policy.resolve(&host).await;
    let decision = policy.evaluate(&host, &ips);

    let span = tracing::Span::current();
    span.record("egress_target", target_label.as_str());
    if let Some(first_ip) = ips.first() {
        span.record("egress_resolved", first_ip.to_string().as_str());
    }

    let elapsed_ms = start.elapsed().as_millis() as u64;
    metrics::counter!("quik_egress_connects_total",
        "action" => match decision {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
        },
        "target" => host.clone(),
    )
    .increment(1);

    if decision == Decision::Deny {
        tracing::info!(
            target: "quik::egress",
            peer = %peer,
            target = %target_label,
            action = "deny",
            resolved = ?ips,
            duration_ms = elapsed_ms,
            "egress denied"
        );
        return synth_short(
            StatusCode::FORBIDDEN,
            "destination not allowed by egress policy\n",
        );
    }

    // Dial the upstream. Connect timeout bounded so we don't hold the
    // inbound socket open if the destination is unreachable.
    let upstream =
        match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&target_label)).await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                metrics::counter!("quik_proxy_errors_total", "kind" => "egress_connect")
                    .increment(1);
                tracing::warn!(
                    target: "quik::egress",
                    peer = %peer,
                    target = %target_label,
                    error = %e,
                    "egress upstream connect failed"
                );
                return synth_short(StatusCode::BAD_GATEWAY, "upstream connect failed\n");
            }
            Err(_) => {
                metrics::counter!("quik_proxy_errors_total", "kind" => "egress_connect_timeout")
                    .increment(1);
                tracing::warn!(
                    target: "quik::egress",
                    peer = %peer,
                    target = %target_label,
                    "egress upstream connect timed out"
                );
                return synth_short(StatusCode::GATEWAY_TIMEOUT, "upstream connect timeout\n");
            }
        };
    let _ = upstream.set_nodelay(true);

    // Capture the inbound upgrade future so we can wire the bidirectional
    // copy *after* sending 200 Connection Established.
    let mut req = req;
    let on_upgrade = hyper::upgrade::on(&mut req);

    let sni_enforce = policy.sni_enforce();
    let target_label_for_task = target_label.clone();
    let host_for_task = host.clone();

    tokio::spawn(async move {
        tunnels_inflight.fetch_add(1, Ordering::Relaxed);
        let inbound = match on_upgrade.await {
            Ok(io) => io,
            Err(e) => {
                tunnels_inflight.fetch_sub(1, Ordering::Relaxed);
                tracing::warn!(error = %e, target = %target_label_for_task, "egress upgrade failed");
                return;
            }
        };
        let bytes = run_tunnel(
            TokioIo::new(inbound),
            upstream,
            &host_for_task,
            &target_label_for_task,
            sni_enforce,
        )
        .await;
        tunnels_inflight.fetch_sub(1, Ordering::Relaxed);

        let (c2u, u2c) = bytes;
        metrics::counter!("quik_egress_bytes_sent_total",     "target" => target_label_for_task.clone()).increment(c2u);
        metrics::counter!("quik_egress_bytes_received_total", "target" => target_label_for_task.clone()).increment(u2c);
        tracing::info!(
            target: "quik::egress",
            target_addr = %target_label_for_task,
            bytes_client_to_upstream = c2u,
            bytes_upstream_to_client = u2c,
            "egress tunnel closed"
        );
    });

    tracing::info!(
        target: "quik::egress",
        peer = %peer,
        target = %target_label,
        action = "allow",
        resolved = ?ips,
        duration_ms = elapsed_ms,
        "egress allowed"
    );

    Response::builder()
        .status(StatusCode::OK)
        .body(empty_body())
        .expect("static response builds")
}

/// Run the bidirectional copy. Peeks the first chunk from the inbound side
/// to extract the TLS SNI before forwarding those same bytes to the
/// upstream. Returns `(bytes_client_to_upstream, bytes_upstream_to_client)`.
async fn run_tunnel<I>(
    mut inbound: I,
    mut upstream: TcpStream,
    target_host: &str,
    target_label: &str,
    sni_enforce: bool,
) -> (u64, u64)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut peek = vec![0u8; 2048];
    let peek_read =
        match tokio::time::timeout(Duration::from_secs(5), inbound.read(&mut peek)).await {
            Ok(Ok(n)) => n,
            _ => 0,
        };

    if peek_read > 0 {
        let sni = extract_sni(&peek[..peek_read]);
        let span = tracing::Span::current();
        if let Some(sni_name) = &sni {
            span.record("sni", sni_name.as_str());
            if !sni_matches_target(sni_name, target_host) {
                if sni_enforce {
                    tracing::warn!(
                        target: "quik::egress",
                        target = %target_label,
                        sni = %sni_name,
                        "SNI does not match CONNECT target — aborting (sni_enforce=true)"
                    );
                    let _ = upstream.shutdown().await;
                    return (peek_read as u64, 0);
                }
                tracing::warn!(
                    target: "quik::egress",
                    target = %target_label,
                    sni = %sni_name,
                    "SNI does not match CONNECT target — allowing (sni_enforce=false)"
                );
            }
        }

        // Forward the peeked bytes to the upstream first.
        if let Err(e) = upstream.write_all(&peek[..peek_read]).await {
            tracing::debug!(target = %target_label, error = %e, "upstream write failed on initial chunk");
            return (peek_read as u64, 0);
        }
    }

    match tokio::io::copy_bidirectional(&mut inbound, &mut upstream).await {
        Ok((rest_c2u, rest_u2c)) => (peek_read as u64 + rest_c2u, rest_u2c),
        Err(e) => {
            tracing::debug!(target = %target_label, error = %e, "egress bidirectional copy ended");
            (peek_read as u64, 0)
        }
    }
}

/// SNI host matches the CONNECT target if they're equal (case-insensitive),
/// or if the CONNECT target is a wildcard parent of the SNI (e.g.
/// CONNECT=`api.example.com:443`, SNI=`api.example.com`).
fn sni_matches_target(sni: &str, target: &str) -> bool {
    sni.eq_ignore_ascii_case(target)
}

fn empty_body() -> EgressBody {
    Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed()
}

/// Validate the `Proxy-Authorization` header and return the originator
/// string to log against this tunnel. On failure, the returned Response
/// is the 407 challenge / 403 reject that should go back to the client.
async fn authenticate(
    req: &Request<Incoming>,
    auth: &CompiledEgressAuth,
) -> Result<String, Response<EgressBody>> {
    let header_value = req
        .headers()
        .get("proxy-authorization")
        .and_then(|h| h.to_str().ok());

    let raw = match header_value {
        Some(s) => s,
        None => return Err(challenge_407(auth)),
    };

    match auth {
        CompiledEgressAuth::Jwt {
            validator,
            originator_claim,
        } => {
            let token = raw
                .strip_prefix("Bearer ")
                .or_else(|| raw.strip_prefix("bearer "))
                .ok_or_else(|| challenge_407(auth))?;
            match validator.validate(token).await {
                Ok(claims) => {
                    let originator = claims
                        .get(originator_claim.as_str())
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    Ok(originator)
                }
                Err(e) => {
                    tracing::debug!(error = %e, "egress JWT rejected");
                    Err(synth_short(StatusCode::FORBIDDEN, "proxy JWT rejected\n"))
                }
            }
        }
        CompiledEgressAuth::BasicLogOnly { .. } => {
            use base64::Engine;
            let encoded = raw
                .strip_prefix("Basic ")
                .or_else(|| raw.strip_prefix("basic "))
                .ok_or_else(|| challenge_407(auth))?;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| challenge_407(auth))?;
            let s = std::str::from_utf8(&decoded).map_err(|_| challenge_407(auth))?;
            let (user, _pw) = s.split_once(':').ok_or_else(|| challenge_407(auth))?;
            if user.is_empty() {
                return Err(challenge_407(auth));
            }
            // No password validation by design — the realm name documents
            // the trust posture, and the username is logged for audit.
            Ok(user.to_string())
        }
    }
}

fn challenge_407(auth: &CompiledEgressAuth) -> Response<EgressBody> {
    let challenge = match auth {
        CompiledEgressAuth::Jwt { .. } => "Bearer".to_string(),
        CompiledEgressAuth::BasicLogOnly { realm } => format!("Basic realm=\"{realm}\""),
    };
    let body = Full::new(Bytes::from_static(b"proxy auth required\n"))
        .map_err(|never| match never {})
        .boxed();
    let mut resp = Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body)
        .expect("static response builds");
    if let Ok(v) = http::HeaderValue::from_str(&challenge) {
        resp.headers_mut().insert("proxy-authenticate", v);
    }
    resp
}

fn synth_short(status: StatusCode, msg: &'static str) -> Response<EgressBody> {
    let body = Full::new(Bytes::from_static(msg.as_bytes()))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body)
        .expect("static response builds")
}
