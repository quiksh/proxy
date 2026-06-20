//! Header hygiene + identity-header generation.
//!
//! Three jobs:
//! - **Hop-by-hop stripping** ([`strip_hop_by_hop`]) per RFC 7230 §6.1, plus
//!   any header name listed inside the `Connection` header itself.
//! - **Identity headers** ([`ensure_request_id`], [`ensure_traceparent`])
//!   pass through inbound values when valid, otherwise generate fresh ones.
//!   IDs are CSPRNG-backed (`getrandom::fill`) - same cost as a non-CSPRNG
//!   on modern OSes and removes any "what if this leaks into an
//!   authorisation context" footgun.
//! - **`X-Forwarded-*` injection.** Whether the inbound chain is trusted is
//!   decided by [`ForwardedPolicy`]:
//!   - untrusted peer (the default in [`Mode::Edge`]): inbound XFF is ignored
//!     (potentially spoofed by an external client) and replaced with the peer
//!     IP.
//!   - trusted peer ([`Mode::Host`], or an edge peer inside `trusted_proxies`):
//!     inbound XFF is appended-to (we trust whoever set it).
//! - **RFC 7239 `Forwarded`** ([`apply_forwarded`]) is emitted with the same
//!   trust model, but only when [`ForwardedPolicy::emit`] is set.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use http::header::{
    CONNECTION, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderMap, HeaderName, HeaderValue};
use ipnet::IpNet;

use crate::config::{ForwardedConfig, Mode};

/// Remove RFC 7230 § 6.1 hop-by-hop headers and any header name listed in the
/// `Connection` header itself. The proxy must not forward these to upstream
/// (or to the inbound client in the response direction).
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let names_in_connection: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .filter_map(|s| HeaderName::try_from(s.trim()).ok())
        .collect();
    for name in names_in_connection {
        headers.remove(&name);
    }
    headers.remove(CONNECTION);
    headers.remove(PROXY_AUTHENTICATE);
    headers.remove(PROXY_AUTHORIZATION);
    headers.remove(TE);
    headers.remove(TRAILER);
    headers.remove(TRANSFER_ENCODING);
    headers.remove(UPGRADE);
    headers.remove("keep-alive");
}

// ── Random helpers (hand-rolled - see audit, replaces the `uuid` dep) ────────

fn fill_random(buf: &mut [u8]) {
    // getrandom failing means the OS RNG is broken; nothing useful to do.
    getrandom::fill(buf).expect("OS RNG unavailable");
}

fn hex_lower(buf: &[u8]) -> String {
    let mut out = String::with_capacity(buf.len() * 2);
    for b in buf {
        out.push(nibble_to_hex(b >> 4));
        out.push(nibble_to_hex(b & 0x0f));
    }
    out
}

fn nibble_to_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => unreachable!(),
    }
}

/// Generate a UUIDv4-shaped string (canonical 8-4-4-4-12 hex).
pub fn random_request_id() -> String {
    let mut b = [0u8; 16];
    fill_random(&mut b);
    // RFC 4122 §4.4: set version (high nibble of byte 6) to 4 and variant
    // (high two bits of byte 8) to RFC 4122 (10b).
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex_lower(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Generate a W3C `traceparent` header value with a fresh trace-id and
/// parent-id, flags set to sampled (`01`).
pub fn random_traceparent() -> String {
    let mut trace = [0u8; 16];
    let mut parent = [0u8; 8];
    fill_random(&mut trace);
    fill_random(&mut parent);
    format!("00-{}-{}-01", hex_lower(&trace), hex_lower(&parent))
}

/// Loose syntactic check on a `traceparent`. Per W3C trace-context §3.2.2:
/// `version-trace_id-parent_id-flags` with sizes 2-32-16-2, all lowercase hex,
/// and trace_id != all zeros, parent_id != all zeros. Versions other than 00
/// are also valid going forward but we accept just-`00` here.
pub fn valid_traceparent(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 4 {
        return false;
    }
    let [v, t, p, f] = [parts[0], parts[1], parts[2], parts[3]];
    if v.len() != 2 || t.len() != 32 || p.len() != 16 || f.len() != 2 {
        return false;
    }
    let is_hex = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    };
    if !is_hex(v) || !is_hex(t) || !is_hex(p) || !is_hex(f) {
        return false;
    }
    if t.bytes().all(|b| b == b'0') || p.bytes().all(|b| b == b'0') {
        return false;
    }
    true
}

// ── Identity-header injection ────────────────────────────────────────────────

/// Pass through `X-Request-ID` if a non-empty value was supplied, otherwise
/// generate a fresh one. Returns the final value so the caller can attach it
/// to log spans.
pub fn ensure_request_id(headers: &mut HeaderMap) -> String {
    if let Some(v) = headers.get("x-request-id")
        && let Ok(s) = v.to_str()
        && !s.is_empty()
    {
        return s.to_string();
    }
    let id = random_request_id();
    if let Ok(v) = HeaderValue::try_from(&id) {
        headers.insert("x-request-id", v);
    }
    id
}

/// Pass through `traceparent` if syntactically valid; otherwise generate a
/// fresh trace context. Returns the final value.
pub fn ensure_traceparent(headers: &mut HeaderMap) -> String {
    if let Some(v) = headers.get("traceparent")
        && let Ok(s) = v.to_str()
        && valid_traceparent(s)
    {
        return s.to_string();
    }
    let tp = random_traceparent();
    if let Ok(v) = HeaderValue::try_from(&tp) {
        headers.insert("traceparent", v);
    }
    tp
}

/// Apply `X-Forwarded-For`:
/// - `trusted == false`: ignore anything inbound (potentially spoofed) and set
///   XFF = peer.
/// - `trusted == true`: append peer to the existing XFF chain (or create it if
///   absent).
///
/// The trust decision is [`ForwardedPolicy::trusts`].
pub fn apply_forwarded_for(headers: &mut HeaderMap, peer: IpAddr, trusted: bool) {
    let peer_str = peer.to_string();
    let new_value = if trusted {
        match headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            Some(existing) if !existing.is_empty() => format!("{existing}, {peer_str}"),
            _ => peer_str,
        }
    } else {
        peer_str
    };
    if let Ok(v) = HeaderValue::try_from(new_value) {
        headers.insert("x-forwarded-for", v);
    }
}

/// Apply the RFC 7239 `Forwarded` header. Mirrors [`apply_forwarded_for`]'s
/// trust model: a trusted peer's existing chain is appended to, an untrusted
/// peer's is replaced. `host` is the inbound `Host` / `:authority`; `proto` is
/// always `https` because the proxy terminates TLS.
///
/// Each element is `for=<node>;host="<host>";proto=https`. Per RFC 7239 §6 an
/// IPv6 `node` must be bracketed and the whole identifier quoted; `host` is
/// quoted defensively because a `Host` with a port contains a `:`, which is not
/// a bare token.
pub fn apply_forwarded(headers: &mut HeaderMap, peer: IpAddr, host: Option<&str>, trusted: bool) {
    let mut element = format!("for={}", forwarded_node(peer));
    if let Some(h) = host
        && !h.contains('"')
    {
        element.push_str(";host=\"");
        element.push_str(h);
        element.push('"');
    }
    element.push_str(";proto=https");

    let new_value = if trusted {
        match headers.get("forwarded").and_then(|v| v.to_str().ok()) {
            Some(existing) if !existing.is_empty() => format!("{existing}, {element}"),
            _ => element,
        }
    } else {
        element
    };
    if let Ok(v) = HeaderValue::try_from(new_value) {
        headers.insert("forwarded", v);
    }
}

/// Format an IP as an RFC 7239 `node` identifier. IPv4 is a bare literal; IPv6
/// is bracketed and quoted because it contains `:`.
fn forwarded_node(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("\"[{v6}]\""),
    }
}

/// Parse a single `trusted_proxies` entry: a CIDR (`10.0.0.0/8`) or a bare IP
/// literal (treated as a single-host `/32` or `/128`). Shared with config
/// validation so a bad entry fails at startup, not silently at runtime.
pub fn parse_trusted_proxy(entry: &str) -> Result<IpNet> {
    if entry.contains('/') {
        entry
            .parse::<IpNet>()
            .with_context(|| format!("invalid CIDR '{entry}'"))
    } else {
        let ip: IpAddr = entry
            .parse()
            .with_context(|| format!("invalid IP literal '{entry}'"))?;
        Ok(match ip {
            IpAddr::V4(v4) => IpNet::V4(v4.into()),
            IpAddr::V6(v6) => IpNet::V6(v6.into()),
        })
    }
}

/// Compiled forwarding policy: which immediate peers we trust to have set the
/// forwarding chain, and whether to also emit RFC 7239 `Forwarded`. Built once
/// at startup from [`ForwardedConfig`] and shared across the hot path.
#[derive(Debug, Default)]
pub struct ForwardedPolicy {
    trusted_proxies: Vec<IpNet>,
    /// Also emit the RFC 7239 `Forwarded` header.
    pub emit: bool,
}

impl ForwardedPolicy {
    /// Compile from config. Entries are assumed pre-validated by
    /// `config::validate`; an unexpected bad entry here is skipped rather than
    /// panicking on the hot path's behalf.
    pub fn from_config(cfg: &ForwardedConfig) -> Self {
        let trusted_proxies = cfg
            .trusted_proxies
            .iter()
            .filter_map(|e| parse_trusted_proxy(e).ok())
            .collect();
        Self {
            trusted_proxies,
            emit: cfg.emit,
        }
    }

    /// Whether we trust the inbound forwarding chain from this peer (and so
    /// should *append* our observed peer rather than *replace* the chain).
    /// `host` mode trusts by definition; `edge` mode trusts only peers inside
    /// `trusted_proxies`.
    pub fn trusts(&self, peer: IpAddr, mode: Mode) -> bool {
        match mode {
            Mode::Host => true,
            Mode::Edge => self.trusted_proxies.iter().any(|n| n.contains(&peer)),
        }
    }
}

/// A [`ForwardedPolicy`] behind an [`ArcSwap`] so a config reload can hot-swap
/// the trusted-proxy set / `emit` toggle without coordinating with in-flight
/// requests. Mirrors [`crate::routing::SharedRoutingTable`]: the hot path does
/// a single lock-free [`load`](Self::load) to read the current policy.
#[derive(Default)]
pub struct SharedForwardedPolicy {
    inner: ArcSwap<ForwardedPolicy>,
}

impl SharedForwardedPolicy {
    pub fn from_config(cfg: &ForwardedConfig) -> Self {
        Self {
            inner: ArcSwap::from_pointee(ForwardedPolicy::from_config(cfg)),
        }
    }

    /// Load the current policy (single Arc clone). Hold the returned guard only
    /// as briefly as the request needs - a reload may replace it afterwards.
    pub fn load(&self) -> arc_swap::Guard<Arc<ForwardedPolicy>> {
        self.inner.load()
    }

    /// Atomically replace the policy. Called by the config-reload path.
    pub fn swap(&self, new: ForwardedPolicy) {
        self.inner.store(Arc::new(new));
    }
}

/// Set `X-Forwarded-Host` to the original inbound Host header (or `:authority`
/// pseudo-header in HTTP/2). Idempotent.
pub fn apply_forwarded_host(headers: &mut HeaderMap, original_host: Option<&str>) {
    if let Some(h) = original_host
        && let Ok(v) = HeaderValue::try_from(h)
    {
        headers.insert("x-forwarded-host", v);
    }
}

/// Set `X-Forwarded-Proto`. We terminate TLS so this is always `https` from
/// the upstream's perspective when called from the proxy hot path.
pub fn apply_forwarded_proto(headers: &mut HeaderMap, scheme: &'static str) {
    if let Ok(v) = HeaderValue::try_from(scheme) {
        headers.insert("x-forwarded-proto", v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{CONNECTION, TRANSFER_ENCODING, UPGRADE};

    #[test]
    fn removes_standard_hop_by_hop() {
        let mut h = HeaderMap::new();
        h.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
        h.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        h.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        h.insert(UPGRADE, HeaderValue::from_static("websocket"));
        h.insert("content-type", HeaderValue::from_static("text/plain"));

        strip_hop_by_hop(&mut h);

        assert!(h.get(CONNECTION).is_none());
        assert!(h.get("keep-alive").is_none());
        assert!(h.get(TRANSFER_ENCODING).is_none());
        assert!(h.get(UPGRADE).is_none());
        assert!(h.get("content-type").is_some());
    }

    #[test]
    fn removes_headers_listed_in_connection() {
        let mut h = HeaderMap::new();
        h.insert(CONNECTION, HeaderValue::from_static("x-foo, x-bar"));
        h.insert("x-foo", HeaderValue::from_static("1"));
        h.insert("x-bar", HeaderValue::from_static("2"));
        h.insert("x-baz", HeaderValue::from_static("3"));

        strip_hop_by_hop(&mut h);

        assert!(h.get("x-foo").is_none());
        assert!(h.get("x-bar").is_none());
        assert!(h.get("x-baz").is_some());
    }

    #[test]
    fn request_id_is_uuidv4_shaped() {
        let id = random_request_id();
        assert_eq!(id.len(), 36);
        // Format: 8-4-4-4-12 with dashes at fixed positions.
        let bytes = id.as_bytes();
        assert_eq!(bytes[8], b'-');
        assert_eq!(bytes[13], b'-');
        assert_eq!(bytes[18], b'-');
        assert_eq!(bytes[23], b'-');
        // Version-4 nibble must be 4.
        assert_eq!(id.chars().nth(14).unwrap(), '4');
        // Variant must be one of 8/9/a/b.
        let variant = id.chars().nth(19).unwrap();
        assert!(matches!(variant, '8' | '9' | 'a' | 'b'));
    }

    #[test]
    fn request_ids_are_unique() {
        let a = random_request_id();
        let b = random_request_id();
        assert_ne!(a, b);
    }

    #[test]
    fn traceparent_format() {
        let tp = random_traceparent();
        assert!(
            valid_traceparent(&tp),
            "generated traceparent should validate: {tp}"
        );
    }

    #[test]
    fn traceparent_validation() {
        assert!(valid_traceparent(
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        ));
        // wrong number of segments
        assert!(!valid_traceparent("00-trace-parent"));
        // uppercase hex disallowed by W3C
        assert!(!valid_traceparent(
            "00-0AF7651916CD43DD8448EB211C80319C-b7ad6b7169203331-01"
        ));
        // all-zero trace-id disallowed
        assert!(!valid_traceparent(
            "00-00000000000000000000000000000000-b7ad6b7169203331-01"
        ));
        // all-zero parent-id disallowed
        assert!(!valid_traceparent(
            "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01"
        ));
    }

    #[test]
    fn ensure_request_id_passes_through_existing() {
        let mut h = HeaderMap::new();
        h.insert("x-request-id", HeaderValue::from_static("abc-123"));
        assert_eq!(ensure_request_id(&mut h), "abc-123");
    }

    #[test]
    fn ensure_request_id_generates_when_absent() {
        let mut h = HeaderMap::new();
        let id = ensure_request_id(&mut h);
        assert_eq!(id.len(), 36);
        assert_eq!(h.get("x-request-id").unwrap(), id.as_str());
    }

    #[test]
    fn xff_untrusted_replaces() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.99")); // spoofed
        apply_forwarded_for(&mut h, "10.0.0.5".parse().unwrap(), false);
        assert_eq!(h.get("x-forwarded-for").unwrap(), "10.0.0.5");
    }

    #[test]
    fn xff_trusted_appends() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.99, 10.0.0.1"),
        );
        apply_forwarded_for(&mut h, "10.0.0.5".parse().unwrap(), true);
        assert_eq!(
            h.get("x-forwarded-for").unwrap(),
            "203.0.113.99, 10.0.0.1, 10.0.0.5"
        );
    }

    #[test]
    fn xff_trusted_creates_when_absent() {
        let mut h = HeaderMap::new();
        apply_forwarded_for(&mut h, "10.0.0.5".parse().unwrap(), true);
        assert_eq!(h.get("x-forwarded-for").unwrap(), "10.0.0.5");
    }

    fn policy(trusted: &[&str], emit: bool) -> ForwardedPolicy {
        ForwardedPolicy::from_config(&ForwardedConfig {
            trusted_proxies: trusted.iter().map(|s| s.to_string()).collect(),
            emit,
        })
    }

    #[test]
    fn host_mode_always_trusts() {
        let p = policy(&[], false);
        assert!(p.trusts("203.0.113.7".parse().unwrap(), Mode::Host));
    }

    #[test]
    fn edge_mode_trusts_only_listed_proxies() {
        let p = policy(&["10.0.0.0/8", "192.168.1.5"], false);
        // CIDR match, exact-IP match, and a non-member.
        assert!(p.trusts("10.4.2.1".parse().unwrap(), Mode::Edge));
        assert!(p.trusts("192.168.1.5".parse().unwrap(), Mode::Edge));
        assert!(!p.trusts("203.0.113.7".parse().unwrap(), Mode::Edge));
    }

    #[test]
    fn edge_mode_with_no_trusted_proxies_trusts_nobody() {
        let p = policy(&[], false);
        assert!(!p.trusts("10.0.0.5".parse().unwrap(), Mode::Edge));
    }

    #[test]
    fn forwarded_untrusted_replaces_with_single_element() {
        let mut h = HeaderMap::new();
        h.insert("forwarded", HeaderValue::from_static("for=1.2.3.4")); // spoofed
        apply_forwarded(
            &mut h,
            "10.0.0.5".parse().unwrap(),
            Some("api.example.com"),
            false,
        );
        assert_eq!(
            h.get("forwarded").unwrap(),
            "for=10.0.0.5;host=\"api.example.com\";proto=https"
        );
    }

    #[test]
    fn forwarded_trusted_appends() {
        let mut h = HeaderMap::new();
        h.insert(
            "forwarded",
            HeaderValue::from_static("for=203.0.113.9;proto=https"),
        );
        apply_forwarded(&mut h, "10.0.0.5".parse().unwrap(), None, true);
        assert_eq!(
            h.get("forwarded").unwrap(),
            "for=203.0.113.9;proto=https, for=10.0.0.5;proto=https"
        );
    }

    #[test]
    fn forwarded_ipv6_node_is_bracketed_and_quoted() {
        let mut h = HeaderMap::new();
        apply_forwarded(&mut h, "2001:db8::1".parse().unwrap(), None, false);
        assert_eq!(
            h.get("forwarded").unwrap(),
            "for=\"[2001:db8::1]\";proto=https"
        );
    }

    #[test]
    fn forwarded_drops_host_containing_quote() {
        // A spoofed Host with an embedded quote must not break out of the
        // quoted-string; we simply omit the host param.
        let mut h = HeaderMap::new();
        apply_forwarded(&mut h, "10.0.0.5".parse().unwrap(), Some("e\"vil"), false);
        assert_eq!(h.get("forwarded").unwrap(), "for=10.0.0.5;proto=https");
    }

    #[test]
    fn parse_trusted_proxy_accepts_cidr_and_bare_ip() {
        assert!(parse_trusted_proxy("10.0.0.0/8").is_ok());
        assert!(parse_trusted_proxy("192.168.1.5").is_ok());
        assert!(parse_trusted_proxy("2001:db8::/32").is_ok());
        assert!(parse_trusted_proxy("not-an-ip").is_err());
        assert!(parse_trusted_proxy("10.0.0.0/99").is_err());
    }
}
