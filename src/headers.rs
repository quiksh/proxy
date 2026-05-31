//! Header hygiene + identity-header generation.
//!
//! Three jobs:
//! - **Hop-by-hop stripping** ([`strip_hop_by_hop`]) per RFC 7230 §6.1, plus
//!   any header name listed inside the `Connection` header itself.
//! - **Identity headers** ([`ensure_request_id`], [`ensure_traceparent`])
//!   pass through inbound values when valid, otherwise generate fresh ones.
//!   IDs are CSPRNG-backed (`getrandom::fill`) — same cost as a non-CSPRNG
//!   on modern OSes and removes any "what if this leaks into an
//!   authorisation context" footgun.
//! - **`X-Forwarded-*` injection.** XFF behaviour is mode-aware:
//!   - [`Mode::Edge`]: inbound XFF is ignored (potentially spoofed by an
//!     external client) and replaced with the peer IP.
//!   - [`Mode::Host`]: inbound XFF is appended-to (we're behind another LB
//!     that we trust to have set it correctly).

use std::net::IpAddr;

use http::header::{
    CONNECTION, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderMap, HeaderName, HeaderValue};

use crate::config::Mode;

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

// ── Random helpers (hand-rolled — see audit, replaces the `uuid` dep) ────────

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

/// Apply `X-Forwarded-For` according to mode:
/// - `edge`: ignore anything inbound (potentially spoofed) and set XFF = peer.
/// - `host`: append peer to the existing XFF chain (or create it if absent).
pub fn apply_forwarded_for(headers: &mut HeaderMap, peer: IpAddr, mode: Mode) {
    let peer_str = peer.to_string();
    let new_value = match mode {
        Mode::Edge => peer_str,
        Mode::Host => match headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            Some(existing) if !existing.is_empty() => format!("{existing}, {peer_str}"),
            _ => peer_str,
        },
    };
    if let Ok(v) = HeaderValue::try_from(new_value) {
        headers.insert("x-forwarded-for", v);
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
    fn xff_edge_mode_replaces() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.99")); // spoofed
        apply_forwarded_for(&mut h, "10.0.0.5".parse().unwrap(), Mode::Edge);
        assert_eq!(h.get("x-forwarded-for").unwrap(), "10.0.0.5");
    }

    #[test]
    fn xff_host_mode_appends() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.99, 10.0.0.1"),
        );
        apply_forwarded_for(&mut h, "10.0.0.5".parse().unwrap(), Mode::Host);
        assert_eq!(
            h.get("x-forwarded-for").unwrap(),
            "203.0.113.99, 10.0.0.1, 10.0.0.5"
        );
    }

    #[test]
    fn xff_host_mode_creates_when_absent() {
        let mut h = HeaderMap::new();
        apply_forwarded_for(&mut h, "10.0.0.5".parse().unwrap(), Mode::Host);
        assert_eq!(h.get("x-forwarded-for").unwrap(), "10.0.0.5");
    }
}
