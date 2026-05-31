//! quik — a low-latency reverse proxy in Rust.
//!
//! Module map (rough request flow on the reverse-proxy path):
//! - [`tls`]: rustls acceptor for the inbound listener (ALPN: h2 + http/1.1).
//! - [`proxy`]: per-connection handler. Spans, header rewriting, module
//!   evaluation (auth, max_body_bytes, timeout, strip_prefix), upstream
//!   selection, response forwarding.
//! - [`routing`]: route table — exact > segment-prefix, longest-prefix-first.
//! - [`upstream`]: per-pool client (TLS + ALPN scoped per-pool), `CountingBody`
//!   byte counters, [`upstream::balance`] LB algorithms, passive health,
//!   [`upstream::state`] (lifecycle + active health), [`upstream::probe`]
//!   (per-pool active health task), [`upstream::drain`] (graceful removal).
//! - [`auth`]: per-route JWT validation with JWKS cache + claim-to-header
//!   injection. Reserved-header protection prevents client spoofing.
//! - [`headers`]: hop-by-hop stripping + identity-header generation
//!   (`request-id`, `traceparent`, `X-Forwarded-*`). CSPRNG-backed IDs.
//! - [`shutdown`]: SIGTERM/SIGINT drain with double-signal force exit.
//! - [`admin`]: separate listener for `/healthz`, `/metrics`, and the
//!   `/admin/pools/*` registration API. Optional TLS + mTLS or bearer auth.
//! - [`observability`]: tracing + metrics init; pre-built handles for hot paths.
//! - [`egress`]: optional second listener — HTTP CONNECT forward proxy with
//!   host/CIDR policy, SNI sniffing, and optional proxy auth.
//! - [`config`]: TOML schema + env-var expansion + validation.

pub mod admin;
pub mod auth;
pub mod config;
pub mod egress;
pub mod headers;
pub mod observability;
pub mod proxy;
pub mod routing;
pub mod shutdown;
pub mod tls;
pub mod upstream;
