//! Inbound HTTP(S) listener + per-request forwarding pipeline.
//!
//! Hot path order inside [`forward_inner`]: route match → auth → max_body
//! pre-check → upstream pick (Balancer increments inflight inside `pick` to
//! avoid stampede) → strip_prefix → header rewrite → body wrapping (limit +
//! counter) → upstream version stamp → request → 5xx-or-success → response
//! head bytes counted → response body wrapped + counted → access log.
//!
//! Non-obvious decisions:
//! - **Per-pool upstream HTTP version.** We do NOT inherit the inbound
//!   version; many backends are h1-only and an inbound h2 request would
//!   surface `UserUnsupportedVersion` from hyper-util. The pool's
//!   `http_version` field drives both ALPN and the stamped request version.
//! - **`request_id` is computed before any early-return.** That way the
//!   404/auth-fail access log carries the correlation id even when we never
//!   touch an upstream.
//! - **Header byte counters are approximations.** We count the logical
//!   (uncompressed) header bytes - useful for capacity / accounting - not
//!   the on-wire HPACK or TLS-record overhead.
//! - **Error chains are unfolded.** hyper-util's `Display` impl shows only
//!   the kind ("Connect"); the real cause (ECONNREFUSED, TLS, DNS, etc.)
//!   lives in `.source()`. See [`error_chain`].
//! - **WebSocket upgrades take a separate path.** `strip_hop_by_hop` would
//!   remove the very headers the upgrade handshake needs.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use http::header::{CONTENT_LENGTH, HOST};
use http::uri::{Parts as UriParts, PathAndQuery};
use http::{Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as ServerBuilder;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::Instrument;

use crate::auth::{AuthError, AuthRegistry, extract_bearer_token};
use crate::config::Mode;
use crate::headers::{
    apply_forwarded_for, apply_forwarded_host, apply_forwarded_proto, ensure_request_id,
    ensure_traceparent, strip_hop_by_hop,
};
use crate::routing::SharedRoutingTable;
use crate::shutdown::Coordinator;
use crate::upstream::{CountingBody, InflightGuard, Pool, ProxyBody};

/// Per-request context that flows through the forward pipeline alongside the
/// borrowed routing table / upstream pool.
#[derive(Clone, Copy)]
pub struct RequestContext {
    pub peer: SocketAddr,
    pub mode: Mode,
}

/// Shared context required by the WebSocket upgrade path. Carries the bits
/// the bidirectional-copy task needs to honour idle timeouts and drain
/// signals. Cheap to clone (Arc + Coordinator clone are both refcount bumps).
#[derive(Clone)]
pub struct WsContext {
    pub limits: Arc<crate::config::ListenerLimitsConfig>,
    pub shutdown: Coordinator,
}

/// Long-lived state shared across every connection on this listener.
#[derive(Clone)]
pub struct ServerState {
    pub routing: Arc<SharedRoutingTable>,
    pub upstreams: Arc<Pool>,
    pub auth: Arc<AuthRegistry>,
    pub mode: Mode,
    /// Defensive timeouts + protocol-level limits applied to every inbound
    /// connection. Cloned cheaply (small POD).
    pub limits: Arc<crate::config::ListenerLimitsConfig>,
}

// Convert any body whose error implements Into<BoxError> into our uniform
// ProxyBody. Used wherever we box a body for the request/response pipeline.
fn into_proxy_body<B>(body: B) -> ProxyBody
where
    B: hyper::body::Body<Data = Bytes> + Send + Sync + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    body.map_err(Into::into).boxed()
}

pub async fn serve(
    listener: TcpListener,
    tls: TlsAcceptor,
    state: ServerState,
    shutdown: Coordinator,
) -> Result<()> {
    let addr = listener.local_addr()?;
    tracing::info!(%addr, "proxy listener bound (TLS)");

    let inbound_count = Arc::new(AtomicU64::new(0));

    loop {
        tokio::select! {
            _ = shutdown.wait_for_drain_start() => {
                tracing::info!("proxy listener stopping accept");
                return Ok(());
            }
            res = listener.accept() => {
                let (tcp, peer) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        metrics::counter!("quik_proxy_errors_total", "kind" => "accept").increment(1);
                        tracing::warn!(error = %e, "tcp accept failed");
                        continue;
                    }
                };
                let _ = tcp.set_nodelay(true);

                let tls = tls.clone();
                let state = state.clone();
                let shutdown = shutdown.clone();
                let inbound_count = inbound_count.clone();

                tokio::spawn(async move {
                    handle_connection(tcp, peer, tls, state, shutdown, inbound_count).await;
                });
            }
        }
    }
}

async fn handle_connection(
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    tls: TlsAcceptor,
    state: ServerState,
    shutdown: Coordinator,
    inbound_count: Arc<AtomicU64>,
) {
    let ctx = RequestContext {
        peer,
        mode: state.mode,
    };
    let tls_start = Instant::now();
    let tls_stream = match tls.accept(tcp).await {
        Ok(s) => {
            metrics::counter!("quik_tls_handshakes_total", "outcome" => "ok").increment(1);
            metrics::histogram!("quik_tls_handshake_seconds")
                .record(tls_start.elapsed().as_secs_f64());
            s
        }
        Err(e) => {
            metrics::counter!("quik_tls_handshakes_total", "outcome" => "error").increment(1);
            tracing::debug!(peer = %peer, error = %e, "tls handshake failed");
            return;
        }
    };

    let n = inbound_count.fetch_add(1, Ordering::Relaxed) + 1;
    metrics::gauge!("quik_inbound_connections").set(n as f64);

    let io = TokioIo::new(tls_stream);

    let ws_ctx = WsContext {
        limits: state.limits.clone(),
        shutdown: shutdown.clone(),
    };
    let mut builder = ServerBuilder::new(TokioExecutor::new());
    apply_listener_limits(&mut builder, &state.limits);

    let svc = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        let ws_ctx = ws_ctx.clone();
        async move {
            let resp = forward(
                req,
                &state.routing,
                &state.upstreams,
                &state.auth,
                ctx,
                ws_ctx,
            )
            .await;
            Ok::<_, Infallible>(resp)
        }
    });

    let conn = builder.serve_connection_with_upgrades(io, svc);
    tokio::pin!(conn);

    tokio::select! {
        r = &mut conn => {
            if let Err(e) = r {
                tracing::debug!(peer = %peer, error = %e, "conn ended with error");
            }
        }
        _ = shutdown.wait_for_drain_start() => {
            conn.as_mut().graceful_shutdown();
            // Three ways out of the grace window: the conn finishes naturally,
            // the grace timer expires, or an operator double-tap forces exit.
            tokio::select! {
                res = &mut conn => match res {
                    Ok(()) => {}
                    Err(e) => tracing::debug!(peer = %peer, error = %e, "conn ended after drain with error"),
                },
                _ = tokio::time::sleep(shutdown.drain_grace()) => {
                    tracing::warn!(peer = %peer, "conn drain timed out, dropping");
                }
                _ = shutdown.wait_for_force() => {
                    tracing::warn!(peer = %peer, "force-exit signalled, dropping conn");
                }
            }
        }
    }

    let n = inbound_count
        .fetch_sub(1, Ordering::Relaxed)
        .saturating_sub(1);
    metrics::gauge!("quik_inbound_connections").set(n as f64);
}

async fn forward(
    req: Request<Incoming>,
    routing: &SharedRoutingTable,
    upstreams: &Pool,
    auth: &AuthRegistry,
    ctx: RequestContext,
    ws_ctx: WsContext,
) -> Response<ProxyBody> {
    // Build the per-request span up front so every log emitted during
    // forward_inner inherits method/path/peer (and, once computed,
    // request_id). The span is entered/exited correctly across awaits
    // via `.instrument()`.
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let span = tracing::info_span!(
        "req",
        method = %method,
        path = %path,
        peer = %ctx.peer,
        request_id = tracing::field::Empty,
    );
    forward_inner(req, routing, upstreams, auth, ctx, ws_ctx)
        .instrument(span)
        .await
}

async fn forward_inner(
    req: Request<Incoming>,
    routing: &SharedRoutingTable,
    upstreams: &Pool,
    auth: &AuthRegistry,
    ctx: RequestContext,
    ws_ctx: WsContext,
) -> Response<ProxyBody> {
    let start = Instant::now();

    // WebSocket upgrades take a dedicated code path so we can preserve the
    // Upgrade/Connection headers and run a bidirectional byte copy after the
    // 101 response.
    if is_websocket_upgrade_request(&req) {
        return handle_ws_upgrade(req, routing, upstreams, auth, ctx, ws_ctx, start).await;
    }

    let (mut parts, body) = req.into_parts();

    // Compute request-id immediately so the span carries it across every
    // downstream log event (including the 404 early-return path).
    let request_id = ensure_request_id(&mut parts.headers);
    tracing::Span::current().record("request_id", request_id.as_str());

    let host = parts
        .headers
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| parts.uri.host());

    let path = parts.uri.path();
    let method = &parts.method;

    let (route_label, pool_name, modules, auth_name) = {
        let table = routing.load();
        let Some(route) = table.match_request(host, method, path) else {
            let none_label: Arc<str> = Arc::from("_none");
            record_terminal(&none_label, 404, start, None);
            return synth(StatusCode::NOT_FOUND, "no route\n");
        };
        (
            route.label.clone(),
            route.upstream_pool.clone(),
            route.modules.clone(),
            route.auth.clone(),
        )
    };

    // ── auth module (per-route JWT validation) ────────────────────────────────
    if let Some(name) = &auth_name {
        let Some(validator) = auth.get(name) else {
            tracing::error!(auth = %name, "route references missing auth - config drift");
            metrics::counter!("quik_proxy_errors_total", "kind" => "auth_misconfig").increment(1);
            record_terminal(&route_label, 500, start, None);
            return synth(StatusCode::INTERNAL_SERVER_ERROR, "auth misconfigured\n");
        };
        // Take an owned copy of the token so the immutable borrow on parts
        // doesn't outlive the call - validate_and_inject needs a mutable
        // borrow on the same HeaderMap to write the injected headers.
        let token = match extract_bearer_token(&parts.headers).map(|t| t.to_owned()) {
            Some(t) => t,
            None => {
                metrics::counter!("quik_auth_total", "auth" => name.clone(), "outcome" => "missing_token").increment(1);
                record_terminal(&route_label, 401, start, None);
                return unauthorized("missing bearer token");
            }
        };
        match validator
            .validate_and_inject(&token, &mut parts.headers)
            .await
        {
            Ok(()) => {
                metrics::counter!("quik_auth_total", "auth" => name.clone(), "outcome" => "ok")
                    .increment(1);
            }
            Err(e) => {
                let outcome = match &e {
                    AuthError::MissingToken => "missing_token",
                    AuthError::MalformedToken => "malformed",
                    AuthError::MissingKid => "missing_kid",
                    AuthError::UnknownKid => "unknown_kid",
                    AuthError::DisallowedAlgorithm => "disallowed_alg",
                    AuthError::InvalidSignature => "bad_signature",
                    AuthError::InvalidClaims(_) => "bad_claims",
                    AuthError::SpoofedHeader(_) => "spoofed_header",
                    AuthError::JwksFetch(_) => "jwks_fetch",
                    AuthError::Other(_) => "other",
                };
                metrics::counter!("quik_auth_total", "auth" => name.clone(), "outcome" => outcome)
                    .increment(1);
                tracing::debug!(auth = %name, error = %e, "auth rejected");
                let status = match e {
                    AuthError::InvalidClaims(_) | AuthError::SpoofedHeader(_) => {
                        StatusCode::FORBIDDEN
                    }
                    _ => StatusCode::UNAUTHORIZED,
                };
                record_terminal(&route_label, status.as_u16(), start, None);
                return unauthorized_with_status(status, "auth rejected");
            }
        }
    }

    // ── max_body_bytes module ────────────────────────────────────────────────
    // Pre-check: any inbound request whose declared Content-Length exceeds
    // the limit is rejected before we open an upstream connection. Streaming
    // bodies without a Content-Length are not currently enforced per-frame.
    if let Some(max) = modules.max_body_bytes
        && let Some(cl) = parts.headers.get(CONTENT_LENGTH)
        && let Ok(s) = cl.to_str()
        && let Ok(n) = s.parse::<u64>()
        && n > max
    {
        metrics::counter!("quik_proxy_errors_total", "kind" => "body_too_large").increment(1);
        record_terminal(&route_label, 413, start, None);
        return synth(StatusCode::PAYLOAD_TOO_LARGE, "body too large\n");
    }

    let pool = match upstreams.get(&pool_name) {
        Some(p) => p,
        None => {
            record_terminal(&route_label, 503, start, None);
            return synth(StatusCode::SERVICE_UNAVAILABLE, "no upstream pool\n");
        }
    };

    // Load the live member list (single Arc clone), pick, then promote the
    // returned &Arc<Upstream> to an owned Arc so the rest of the request
    // outlives the snapshot - an admin writer may swap the member list at
    // any point. The chosen Arc<Upstream> stays valid because its refcount
    // is held by this request frame.
    let members_snap = pool.members_snapshot();
    let target = match pool.balancer.pick(&members_snap) {
        Some(t) => Arc::clone(t),
        None => {
            // Either no members or all members are ejected. Operators see
            // which via the `quik_upstream_state` gauge in /metrics.
            metrics::counter!("quik_proxy_errors_total", "kind" => "no_eligible_upstream")
                .increment(1);
            record_terminal(&route_label, 503, start, None);
            return synth(StatusCode::SERVICE_UNAVAILABLE, "no upstream available\n");
        }
    };
    drop(members_snap);

    metrics::counter!("quik_upstream_selected_total",
        "pool" => pool_name.clone(),
        "member" => target.name.clone()
    )
    .increment(1);

    // Inflight tracking + health recording. The Balancer already
    // incremented inflight when it picked the member; this guard only
    // handles the matching decrement on every exit path.
    let target_health = target.health.clone();
    let target_name = target.name.clone();
    let _inflight_guard = InflightGuard::for_picked(target_health.clone());

    // ── strip_prefix module ──────────────────────────────────────────────────
    let new_paq = rewrite_path_and_query(&parts.uri, modules.strip_prefix.as_deref());

    let mut uri_parts = UriParts::default();
    uri_parts.scheme = Some(target.scheme.clone());
    uri_parts.authority = Some(target.authority.clone());
    uri_parts.path_and_query = Some(new_paq);

    let new_uri = match Uri::from_parts(uri_parts) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "URI assembly failed");
            record_terminal(&route_label, 502, start, Some(&target_name));
            return synth(StatusCode::BAD_GATEWAY, "bad gateway\n");
        }
    };

    // Capture the inbound host before we strip it; X-Forwarded-Host will use it.
    let inbound_host_owned = parts
        .headers
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| parts.uri.host())
        .map(|s| s.to_string());

    parts.uri = new_uri;
    // Upstream HTTP version is decided per-pool via config - NOT inherited
    // from the inbound request. Inheriting h2 to a backend that's h1-only
    // (Proxmox, lots of admin UIs, most legacy APIs) produces hyper-util's
    // `UserUnsupportedVersion`. Default is h1; opt into h2 per pool only
    // for backends you've verified speak it (e.g. gRPC). The connector's
    // ALPN advertisement is matched, so the negotiated TLS connection is
    // always the correct protocol - see upstream::build_client.
    parts.version = match pool.http_version {
        crate::config::UpstreamHttpVersion::H1 => http::Version::HTTP_11,
        crate::config::UpstreamHttpVersion::H2 => http::Version::HTTP_2,
    };
    strip_hop_by_hop(&mut parts.headers);
    parts.headers.remove(HOST);

    // ── identity / forwarding headers ────────────────────────────────────────
    // request_id was already added near the top of this function so the span
    // carries it from early failures too. We only inject the remaining ones
    // here, on the upstream-bound request.
    let _traceparent = ensure_traceparent(&mut parts.headers);
    apply_forwarded_for(&mut parts.headers, ctx.peer.ip(), ctx.mode);
    apply_forwarded_host(&mut parts.headers, inbound_host_owned.as_deref());
    // We always terminate TLS on the inbound side, so upstream sees https.
    apply_forwarded_proto(&mut parts.headers, "https");

    // ── max_body_bytes stream enforcement ────────────────────────────────────
    // Content-Length pre-check above handles the declared-size case. For
    // chunked / streaming uploads without Content-Length, wrap the body so it
    // errors past the byte limit. The upstream sees a body-read failure,
    // which surfaces to us as a normal upstream error response - the client
    // doesn't get a 413 for the chunked case (we've already started forwarding).
    let body: ProxyBody = match modules.max_body_bytes {
        Some(max) => into_proxy_body(Limited::new(body, max as usize)),
        None => into_proxy_body(body),
    };
    // Bytes-sent counter: every data frame on this body (proxy → upstream)
    // adds to the per-member quik_upstream_bytes_sent_total counter.
    let body: ProxyBody = into_proxy_body(CountingBody::new(body, target.bytes_sent.clone()));
    let out_req = Request::from_parts(parts, body);

    // Approximate headers + request line into the sent counter. Approximate
    // because HTTP/2 sends HPACK-compressed headers on the wire - we count
    // the logical (uncompressed) size, which is more useful as a "what does
    // this request actually contain" signal than the on-wire byte count.
    // The body counter (above) continues counting data frames as they
    // stream.
    target
        .bytes_sent
        .increment(approx_request_head_size(&out_req));

    // ── timeout module ───────────────────────────────────────────────────────
    let response_future = pool.client.request(out_req);
    let resp_result = match modules.timeout_ms {
        Some(ms) => match tokio::time::timeout(Duration::from_millis(ms), response_future).await {
            Ok(r) => r,
            Err(_) => {
                tracing::warn!(upstream = %target_name, timeout_ms = ms, "upstream timeout");
                metrics::counter!("quik_proxy_errors_total", "kind" => "timeout").increment(1);
                fire_failure(&target_health, &pool_name, &target_name);
                record_terminal(&route_label, 504, start, Some(&target_name));
                return synth(StatusCode::GATEWAY_TIMEOUT, "upstream timeout\n");
            }
        },
        None => response_future.await,
    };

    let resp = match resp_result {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %error_chain(&e), upstream = %target_name, "upstream error");
            metrics::counter!("quik_proxy_errors_total", "kind" => "upstream_request").increment(1);
            fire_failure(&target_health, &pool_name, &target_name);
            record_terminal(&route_label, 502, start, Some(&target_name));
            return synth(StatusCode::BAD_GATEWAY, "upstream error\n");
        }
    };

    let status = resp.status();
    // 5xx counts as a backend health failure; everything else (including
    // 4xx client errors) is a success from the backend's perspective.
    if status.is_server_error() {
        fire_failure(&target_health, &pool_name, &target_name);
    } else {
        let _was_ejected = target_health.record_success();
    }

    let (mut resp_parts, resp_body) = resp.into_parts();
    // Count response head bytes BEFORE strip_hop_by_hop mutates the headers -
    // we want to attribute what arrived from the upstream, not what we then
    // chose to forward.
    target
        .bytes_received
        .increment(approx_response_head_size(&resp_parts));
    strip_hop_by_hop(&mut resp_parts.headers);
    // Bytes-received counter on the response stream (upstream → client).
    let resp_body: ProxyBody =
        into_proxy_body(CountingBody::new(resp_body, target.bytes_received.clone()));
    let out = Response::from_parts(resp_parts, resp_body);

    record_terminal(&route_label, status.as_u16(), start, Some(&target_name));

    out
}

/// Approximate the byte size of a request's "head" (request line + headers).
/// HTTP/1.1: very close to wire bytes. HTTP/2: HPACK on the wire is smaller,
/// but the *logical* size counted here is the more useful "what's in the
/// request" signal for capacity planning + per-tenant accounting.
fn approx_request_head_size<B>(req: &Request<B>) -> u64 {
    let method = req.method().as_str().len() as u64;
    let path = req.uri().path().len() as u64;
    let query = req.uri().query().map(|q| q.len() as u64 + 1).unwrap_or(0);
    let request_line = method + 1 + path + query + 11; // " HTTP/1.1\r\n"
    request_line + headers_byte_size(req.headers())
}

/// Same idea for a response - status line + headers.
fn approx_response_head_size(parts: &http::response::Parts) -> u64 {
    // "HTTP/1.1 ddd RR\r\n" - 9 for "HTTP/1.1 ", 3 for status code,
    // 1 for space, len of reason phrase, 2 for CRLF
    let reason_len = parts
        .status
        .canonical_reason()
        .map(|r| r.len() as u64)
        .unwrap_or(0);
    let status_line = 9 + 3 + 1 + reason_len + 2;
    status_line + headers_byte_size(&parts.headers)
}

fn headers_byte_size(headers: &http::HeaderMap) -> u64 {
    // "Name: value\r\n" - 2 for ": ", 2 for CRLF, plus the final CRLF
    // separator between headers and body.
    headers
        .iter()
        .map(|(name, value)| (name.as_str().len() + value.as_bytes().len() + 4) as u64)
        .sum::<u64>()
        + 2
}

/// Walk an error chain into a single string. hyper-util's `Display` impl is
/// just the error kind ("Connect", "Body", etc.) - the actual cause is in
/// `.source()`. Without this helper, operators see "Connect" and have no
/// idea whether it was refused / unreachable / TLS / DNS / etc.
fn error_chain<E: std::error::Error + ?Sized>(e: &E) -> String {
    let mut out = e.to_string();
    let mut src: Option<&(dyn std::error::Error + 'static)> = e.source();
    while let Some(cause) = src {
        use std::fmt::Write;
        let _ = write!(&mut out, ": {cause}");
        src = cause.source();
    }
    out
}

/// Record a failure against an upstream member's health state. If this is
/// the failure that crosses the ejection threshold, also fire the ejection
/// counter + a warning log so operators can correlate. Keeps the metric
/// call out of the steady-state success path.
fn fire_failure(health: &crate::upstream::UpstreamHealth, pool_name: &str, member_name: &str) {
    if health.record_failure() {
        metrics::counter!("quik_upstream_ejections_total",
            "pool" => pool_name.to_string(),
            "member" => member_name.to_string()
        )
        .increment(1);
        tracing::warn!(
            pool = %pool_name,
            member = %member_name,
            "ejecting unhealthy upstream"
        );
    }
}

fn record_terminal(route: &Arc<str>, status: u16, start: Instant, upstream: Option<&str>) {
    let duration = start.elapsed();
    metrics::counter!("quik_requests_total",
        "route" => route.to_string(),
        "status" => status.to_string()
    )
    .increment(1);
    metrics::histogram!("quik_request_duration_seconds",
        "route" => route.to_string()
    )
    .record(duration.as_secs_f64());

    // Single structured access-log event per request. Span context attaches
    // method/path/peer/request_id automatically - we only emit the fields
    // that aren't already on the span. Operators can silence access with
    // `RUST_LOG=quik::access=off` or isolate with `quik::access=info,quik=warn`.
    tracing::info!(
        target: "quik::access",
        status,
        duration_ms = duration.as_millis() as u64,
        route = %route,
        upstream = upstream.unwrap_or("-"),
        "access"
    );
}

/// Apply the strip_prefix module: if the request path starts with `strip` as a
/// proper segment prefix, remove that prefix before forwarding. Preserves the
/// query string. Falls back to the original PathAndQuery when no module is set
/// or the prefix doesn't apply.
fn rewrite_path_and_query(uri: &Uri, strip: Option<&str>) -> PathAndQuery {
    let original = uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));

    let Some(strip) = strip else {
        return original;
    };

    let path = uri.path();
    if !path.starts_with(strip) {
        return original;
    }
    let rest = &path[strip.len()..];
    // Only strip on a segment boundary; avoid /api stripping from /apifoo.
    let stripped_path: &str = if rest.is_empty() {
        "/"
    } else if rest.starts_with('/') || strip.ends_with('/') {
        rest
    } else {
        return original;
    };

    let new_paq: String = match uri.query() {
        Some(q) => format!("{stripped_path}?{q}"),
        None => stripped_path.to_string(),
    };
    new_paq
        .parse::<PathAndQuery>()
        .unwrap_or_else(|_| PathAndQuery::from_static("/"))
}

/// Configure the inbound hyper-util ServerBuilder from the parsed limits.
/// Each knob is only applied when set to a non-zero value - operators who
/// want to defer to hyper-util's default for a particular axis can set 0.
fn apply_listener_limits(
    builder: &mut ServerBuilder<TokioExecutor>,
    limits: &crate::config::ListenerLimitsConfig,
) {
    // Header-read and h2 keep-alive timers require an explicit timer impl
    // - without this, hyper panics at runtime when the timer fires.
    builder.http1().timer(TokioTimer::new());
    builder.http2().timer(TokioTimer::new());

    if limits.header_read_timeout_ms > 0 {
        builder
            .http1()
            .header_read_timeout(Duration::from_millis(limits.header_read_timeout_ms));
    }
    if limits.http2_keep_alive_interval_ms > 0 {
        builder
            .http2()
            .keep_alive_interval(Some(Duration::from_millis(
                limits.http2_keep_alive_interval_ms,
            )))
            .keep_alive_timeout(Duration::from_millis(limits.http2_keep_alive_timeout_ms));
    }
    builder
        .http2()
        .max_concurrent_streams(limits.http2_max_concurrent_streams);
}

fn is_websocket_upgrade_request(req: &Request<Incoming>) -> bool {
    if req.method() != http::Method::GET {
        return false;
    }
    let upgrade_ws = req
        .headers()
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("websocket"))
        })
        .unwrap_or(false);
    let conn_upgrade = req
        .headers()
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
    upgrade_ws && conn_upgrade
}

async fn handle_ws_upgrade(
    mut req: Request<Incoming>,
    routing: &SharedRoutingTable,
    upstreams: &Pool,
    _auth: &AuthRegistry,
    ctx: RequestContext,
    ws_ctx: WsContext,
    start: Instant,
) -> Response<ProxyBody> {
    // Mirror forward_inner: stamp the request_id onto the parent "req" span
    // so even early-return paths (no-route etc.) get the correlation key in
    // the access log.
    let request_id = ensure_request_id(req.headers_mut());
    tracing::Span::current().record("request_id", request_id.as_str());

    let host = req
        .headers()
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| req.uri().host());
    let path = req.uri().path();
    let method = req.method().clone();

    let (route_label, pool_name) = {
        let table = routing.load();
        let Some(route) = table.match_request(host, &method, path) else {
            let none_label: Arc<str> = Arc::from("_none");
            record_terminal(&none_label, 404, start, None);
            return synth(StatusCode::NOT_FOUND, "no route\n");
        };
        (route.label.clone(), route.upstream_pool.clone())
    };

    let pool = match upstreams.get(&pool_name) {
        Some(p) => p,
        None => {
            record_terminal(&route_label, 503, start, None);
            return synth(StatusCode::SERVICE_UNAVAILABLE, "no upstream pool\n");
        }
    };

    let members_snap = pool.members_snapshot();
    let target = match pool.balancer.pick(&members_snap) {
        Some(t) => Arc::clone(t),
        None => {
            record_terminal(&route_label, 503, start, None);
            return synth(StatusCode::SERVICE_UNAVAILABLE, "no upstream available\n");
        }
    };
    drop(members_snap);

    metrics::counter!("quik_upstream_selected_total",
        "pool" => pool_name.clone(),
        "member" => target.name.clone()
    )
    .increment(1);

    let target_name = target.name.clone();
    let target_authority = target.authority.clone();
    let target_scheme = target.scheme.clone();

    // Capture inbound upgrade BEFORE we move the request.
    let inbound_upgrade = hyper::upgrade::on(&mut req);

    let (mut parts, body) = req.into_parts();

    let mut uri_parts = UriParts::default();
    uri_parts.scheme = Some(target_scheme);
    uri_parts.authority = Some(target_authority);
    uri_parts.path_and_query = Some(
        parts
            .uri
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| PathAndQuery::from_static("/")),
    );
    let new_uri = match Uri::from_parts(uri_parts) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "ws URI assembly failed");
            record_terminal(&route_label, 502, start, Some(&target_name));
            return synth(StatusCode::BAD_GATEWAY, "bad gateway\n");
        }
    };

    // Capture inbound host before we strip it.
    let inbound_host_owned = parts
        .headers
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    parts.uri = new_uri;
    parts.version = http::Version::HTTP_11; // WS handshake is HTTP/1.1
    parts.headers.remove(HOST);
    // IMPORTANT: do NOT call strip_hop_by_hop on a WS upgrade - Upgrade and
    // Connection must be forwarded for the handshake.

    // Identity / forwarding headers still apply on WS upgrades - the backend
    // wants to know the original client IP / host even for upgrades.
    ensure_request_id(&mut parts.headers);
    ensure_traceparent(&mut parts.headers);
    apply_forwarded_for(&mut parts.headers, ctx.peer.ip(), ctx.mode);
    apply_forwarded_host(&mut parts.headers, inbound_host_owned.as_deref());
    apply_forwarded_proto(&mut parts.headers, "https");

    let body: ProxyBody = into_proxy_body(body);
    let out_req = Request::from_parts(parts, body);

    let mut upstream_resp = match pool.client.request(out_req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %error_chain(&e), upstream = %target_name, "ws upstream request error");
            metrics::counter!("quik_proxy_errors_total", "kind" => "upstream_request").increment(1);
            record_terminal(&route_label, 502, start, Some(&target_name));
            return synth(StatusCode::BAD_GATEWAY, "upstream error\n");
        }
    };

    let status = upstream_resp.status();

    if status != StatusCode::SWITCHING_PROTOCOLS {
        // Upstream declined the upgrade - pass its response through unmodified.
        let (parts, body) = upstream_resp.into_parts();
        record_terminal(&route_label, status.as_u16(), start, Some(&target_name));
        return Response::from_parts(parts, into_proxy_body(body));
    }

    let upstream_upgrade = hyper::upgrade::on(&mut upstream_resp);

    // Clone for the spawned bidirectional-copy task; we still need the
    // original below for the access log on the 101 response.
    let target_name_for_task = target_name.clone();
    let target_name = target_name_for_task.clone();
    let idle_timeout_ms = ws_ctx.limits.websocket_idle_timeout_ms;
    let shutdown_for_task = ws_ctx.shutdown.clone();
    tokio::spawn(async move {
        let target_name = target_name_for_task;
        let inbound_io = match inbound_upgrade.await {
            Ok(io) => io,
            Err(e) => {
                tracing::warn!(error = %e, "inbound ws upgrade failed");
                return;
            }
        };
        let upstream_io = match upstream_upgrade.await {
            Ok(io) => io,
            Err(e) => {
                tracing::warn!(error = %e, upstream = %target_name, "upstream ws upgrade failed");
                return;
            }
        };
        let mut inbound = TokioIo::new(inbound_io);
        let mut upstream = TokioIo::new(upstream_io);

        // Race the bidirectional copy against drain. On drain start the
        // tunnel is dropped - clients on long-lived WS connections see a
        // disconnect and reconnect against the new proxy. This is the
        // expected behaviour for graceful proxy rollover.
        let copy = tokio::io::copy_bidirectional(&mut inbound, &mut upstream);
        let copy = async {
            if idle_timeout_ms > 0 {
                // Wrap each direction-pump in a per-poll idle deadline is
                // fiddly with copy_bidirectional. The pragmatic shape is a
                // hard upper-bound deadline that resets when application
                // pings traverse the tunnel. WS protocols that need long
                // idle periods (>5min default) set their own ping interval
                // shorter than this - the idle timeout culls tunnels with
                // no application-level keepalive at all.
                let deadline = Duration::from_millis(idle_timeout_ms);
                match tokio::time::timeout(deadline, copy).await {
                    Ok(r) => r,
                    Err(_) => {
                        tracing::info!(
                            upstream = %target_name,
                            idle_timeout_ms,
                            "ws tunnel idle timeout"
                        );
                        Ok((0u64, 0u64))
                    }
                }
            } else {
                copy.await
            }
        };

        tokio::select! {
            r = copy => match r {
                Ok((c2u, u2c)) => tracing::debug!(
                    upstream = %target_name,
                    bytes_client_to_upstream = c2u,
                    bytes_upstream_to_client = u2c,
                    "ws bidirectional copy completed"
                ),
                Err(e) => tracing::debug!(
                    error = %e, upstream = %target_name,
                    "ws bidirectional copy ended with error"
                ),
            },
            _ = shutdown_for_task.wait_for_drain_start() => {
                tracing::info!(
                    upstream = %target_name,
                    "ws tunnel closed on drain - client should reconnect"
                );
            }
        }
    });

    let (parts, body) = upstream_resp.into_parts();
    record_terminal(&route_label, 101, start, Some(&target_name));
    Response::from_parts(parts, into_proxy_body(body))
}

fn unauthorized(msg: &'static str) -> Response<ProxyBody> {
    unauthorized_with_status(StatusCode::UNAUTHORIZED, msg)
}

fn unauthorized_with_status(status: StatusCode, msg: &'static str) -> Response<ProxyBody> {
    let body = into_proxy_body(Full::new(Bytes::from_static(msg.as_bytes())));
    let mut resp = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body)
        .expect("static response builds");
    if status == StatusCode::UNAUTHORIZED {
        resp.headers_mut().insert(
            http::header::WWW_AUTHENTICATE,
            http::HeaderValue::from_static("Bearer"),
        );
    }
    resp
}

fn synth(status: StatusCode, msg: &'static str) -> Response<ProxyBody> {
    let body = into_proxy_body(Full::new(Bytes::from_static(msg.as_bytes())));
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body)
        .expect("static response builds")
}
