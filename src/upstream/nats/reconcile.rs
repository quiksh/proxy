//! Pure reconciliation helpers for the NATS watcher.
//!
//! SECURITY: this module is the trust boundary for self-registration. The KV
//! bucket is a control plane for traffic routing and every registration value
//! (`address` especially) is **self-asserted by whoever holds a write
//! credential** - treat it as attacker-controlled. The defences live here:
//! - Allow-list - [`address_allowed`] / [`connect_host`]: the registrable-address
//!   allow-list, parsed with the *same* parser quik connects through so the host
//!   validated is the host dialled (no SSRF via parser differential).
//! - Member caps - [`admit`]: per-pool / per-service member caps.
//!
//! No async-nats types appear here, so all of this is unit-tested without a
//! server. See `docs/service-registration.md` §Security.

use std::collections::HashSet;
use std::net::IpAddr;

use http::uri::Authority;
use ipnet::IpNet;
use serde::Deserialize;

/// A backend's self-registration: the JSON value stored at a `reg.*` key. Extra
/// fields (e.g. `weight`, `metadata`) are accepted and ignored for now.
#[derive(Debug, Clone, Deserialize)]
pub struct Registration {
    pub address: String,
    #[serde(default = "default_scheme")]
    pub scheme: String,
}

fn default_scheme() -> String {
    "http".to_string()
}

/// Parse a KV value into a [`Registration`].
pub fn parse(value: &[u8]) -> Result<Registration, serde_json::Error> {
    serde_json::from_slice(value)
}

/// The service subtree of a registration key - everything but the final
/// (instance) token: `reg.shop.checkout.checkout-1` → `reg.shop.checkout`.
pub fn service_prefix(key: &str) -> &str {
    key.rsplit_once('.').map(|(p, _)| p).unwrap_or(key)
}

/// The identity suffix shared by a `reg.*` key and its `override.*` counterpart:
/// the key with its first token dropped. `reg.shop.checkout.c1` and
/// `override.shop.checkout.c1` both → `shop.checkout.c1`.
pub fn identity_suffix(key: &str) -> &str {
    key.split_once('.').map(|(_, rest)| rest).unwrap_or(key)
}

/// Why a registration was refused - the `quik_nats_registration_rejected_total`
/// reason label and the audit outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Address outside the pool's allow-list.
    Address,
    /// Pool member cap reached (backstop).
    PoolCap,
    /// Per-service instance quota reached.
    ServiceQuota,
}

impl Reject {
    pub fn as_str(self) -> &'static str {
        match self {
            Reject::Address => "address_not_allowed",
            Reject::PoolCap => "pool_member_cap",
            Reject::ServiceQuota => "service_quota",
        }
    }
}

/// An allow-list entry, parsed once from its config string (see [`compile_allow`])
/// so admission checks don't re-parse CIDRs/IPs on every registration event.
#[derive(Debug, Clone)]
pub enum AllowEntry {
    /// A CIDR block, e.g. `10.0.0.0/8`.
    Cidr(IpNet),
    /// A single IP, e.g. `10.0.0.5`.
    Ip(IpAddr),
    /// A host-suffix (leading dots trimmed, never empty), e.g. `svc.local`.
    Suffix(String),
}

/// Parse a config allow-list into [`AllowEntry`]s once. An entry is a CIDR, then
/// a bare IP, else a host-suffix; empty/dot-only entries are dropped (they would
/// match nothing, as the string form did). Call once per pool, not per event.
pub fn compile_allow(allow: &[String]) -> Vec<AllowEntry> {
    allow
        .iter()
        .filter_map(|entry| {
            if let Ok(net) = entry.parse::<IpNet>() {
                Some(AllowEntry::Cidr(net))
            } else if let Ok(ip) = entry.parse::<IpAddr>() {
                Some(AllowEntry::Ip(ip))
            } else {
                let suffix = entry.trim_start_matches('.');
                (!suffix.is_empty()).then(|| AllowEntry::Suffix(suffix.to_string()))
            }
        })
        .collect()
}

/// SECURITY: the admission gate (allow-list + member caps). Decide whether a `reg` key carrying a
/// self-asserted `addr` may be admitted, given the keys already accepted this
/// pass (the watcher's authoritative view of `Nats`-sourced members), the
/// allow-list, and the caps. Address is checked before any slot is
/// counted; re-registration of an already-accepted key never consumes a fresh
/// slot. Pure, so the gate is exhaustively unit-tested.
pub fn admit(
    key: &str,
    addr: &str,
    accepted: &HashSet<String>,
    allow: &[AllowEntry],
    max_members: Option<u32>,
    max_instances_per_service: Option<u32>,
) -> Result<(), Reject> {
    if !address_allowed(addr, allow) {
        return Err(Reject::Address);
    }
    let is_new = !accepted.contains(key);
    if is_new
        && let Some(cap) = max_members
        && accepted.len() as u32 >= cap
    {
        return Err(Reject::PoolCap);
    }
    if is_new && let Some(cap) = max_instances_per_service {
        let prefix = service_prefix(key);
        let count = accepted
            .iter()
            .filter(|k| service_prefix(k) == prefix)
            .count() as u32;
        if count >= cap {
            return Err(Reject::ServiceQuota);
        }
    }
    Ok(())
}

/// True if `addr`'s host is permitted by the (pre-compiled) allow-list. An IP
/// host matches `Cidr`/`Ip` entries; a hostname host matches `Suffix` entries.
/// An empty allow-list - or an address that doesn't parse - denies (fail-safe).
///
/// The host is extracted with the **same parser quik connects through**
/// (`http::uri::Authority`, as in `build_member`), so the host validated here is
/// byte-for-byte the host quik dials. This closes the parser-differential where a
/// crafted address (`[10.0.0.5]@169.254.169.254:80`) showed an allow-listed host
/// to a naive check while quik connected to an SSRF target.
pub fn address_allowed(addr: &str, allow: &[AllowEntry]) -> bool {
    let Some(host) = connect_host(addr) else {
        return false;
    };
    let host_ip = host.parse::<IpAddr>().ok();
    allow.iter().any(|entry| match (entry, host_ip) {
        (AllowEntry::Cidr(net), Some(ip)) => net.contains(&ip),
        (AllowEntry::Ip(eip), Some(ip)) => *eip == ip,
        (AllowEntry::Suffix(suffix), None) => {
            host == *suffix || host.ends_with(&format!(".{suffix}"))
        }
        _ => false,
    })
}

/// The host quik will actually connect to for `addr`, parsed exactly as
/// `build_member` does. Returns `None` - i.e. deny - if the address carries
/// userinfo (`@`, never legitimate in an upstream address and the lever for the
/// parser-differential) or fails to parse as a bare authority. IPv6 brackets are
/// stripped so the result feeds `IpAddr::parse`.
fn connect_host(addr: &str) -> Option<String> {
    if addr.contains('@') {
        return None;
    }
    let authority = addr.parse::<Authority>().ok()?;
    let host = authority.host();
    if host.is_empty() {
        return None;
    }
    Some(
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a set of already-accepted keys.
    fn accepted(keys: &[&str]) -> HashSet<String> {
        keys.iter().map(|k| k.to_string()).collect()
    }

    /// Compile a `&str` allow-list for tests.
    fn al(entries: &[&str]) -> Vec<AllowEntry> {
        compile_allow(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn compile_allow_classifies_and_drops_empty() {
        let c = al(&["10.0.0.0/8", "10.0.0.5", ".svc.local", "", "."]);
        // CIDR, IP, suffix kept; empty and dot-only dropped.
        assert_eq!(c.len(), 3);
        assert!(matches!(c[0], AllowEntry::Cidr(_)));
        assert!(matches!(c[1], AllowEntry::Ip(_)));
        assert!(matches!(&c[2], AllowEntry::Suffix(s) if s == "svc.local"));
    }

    #[test]
    fn cidr_allow_accepts_in_range_rejects_out() {
        let allow = al(&["10.0.0.0/8"]);
        assert!(address_allowed("10.4.5.6:8080", &allow));
        assert!(!address_allowed("192.168.1.1:8080", &allow));
        // The classic SSRF target must be rejected by a 10/8 allow-list.
        assert!(!address_allowed("169.254.169.254:80", &allow));
    }

    #[test]
    fn bare_ip_and_ipv6_bracket() {
        let allow = al(&["10.0.0.5", "fd00::/8"]);
        assert!(address_allowed("10.0.0.5:9000", &allow));
        assert!(!address_allowed("10.0.0.6:9000", &allow));
        assert!(address_allowed("[fd00::1]:8080", &allow));
        assert!(!address_allowed("[fe80::1]:8080", &allow));
    }

    #[test]
    fn host_suffix_match() {
        let allow = al(&[".svc.cluster.local"]);
        assert!(address_allowed("checkout-1.svc.cluster.local:8080", &allow));
        assert!(address_allowed("svc.cluster.local:8080", &allow));
        assert!(!address_allowed("evil.example.com:8080", &allow));
        // A hostname must not be admitted by a CIDR-only allow-list.
        assert!(!address_allowed(
            "checkout.internal:8080",
            &al(&["10.0.0.0/8"])
        ));
    }

    #[test]
    fn empty_allow_list_denies_all() {
        assert!(!address_allowed("10.0.0.1:8080", &[]));
    }

    #[test]
    fn rejects_parser_differential_ssrf() {
        // A naive `host:port` split saw an allow-listed 10.0.0.5 here, but quik
        // (http::uri::Authority) connects to 169.254.169.254 - the userinfo `@`
        // must make these deny, for both CIDR and suffix allow-lists.
        let cidr = al(&["10.0.0.0/8"]);
        assert!(!address_allowed("[10.0.0.5]@169.254.169.254:80", &cidr));
        assert!(!address_allowed("10.0.0.5@169.254.169.254:80", &cidr));
        let suffix = al(&[".svc"]);
        assert!(!address_allowed("x.svc@169.254.169.254:80", &suffix));
        // Anything with userinfo is denied regardless of where it points.
        assert!(!address_allowed("a@b.svc:80", &suffix));
        // Sanity: the legitimate forms still pass / the bare target still fails.
        assert!(address_allowed("10.0.0.5:8080", &cidr));
        assert!(address_allowed("checkout.svc:8080", &suffix));
        assert!(!address_allowed("169.254.169.254:80", &cidr));
        // Unparseable junk denies (fail-safe).
        assert!(!address_allowed("not a host", &cidr));
    }

    #[test]
    fn admit_rejects_bad_address() {
        let err = admit(
            "reg.shop.checkout.c1",
            "169.254.169.254:80",
            &accepted(&[]),
            &al(&["10.0.0.0/8"]),
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(err, Reject::Address);
    }

    #[test]
    fn admit_enforces_pool_cap_but_allows_refresh() {
        let d = accepted(&["reg.shop.checkout.c1", "reg.shop.checkout.c2"]);
        let allow = al(&["10.0.0.0/8"]);
        // New member beyond the cap of 2 → rejected.
        assert_eq!(
            admit(
                "reg.shop.checkout.c3",
                "10.0.0.3:8080",
                &d,
                &allow,
                Some(2),
                None
            ),
            Err(Reject::PoolCap)
        );
        // Re-registering an existing key does not consume a new slot.
        assert!(
            admit(
                "reg.shop.checkout.c1",
                "10.0.0.1:8080",
                &d,
                &allow,
                Some(2),
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn admit_enforces_per_service_quota() {
        // A different service (cart) is unaffected by checkout's quota.
        let d = accepted(&[
            "reg.shop.checkout.c1",
            "reg.shop.checkout.c2",
            "reg.shop.cart.a1",
        ]);
        let allow = al(&["10.0.0.0/8"]);
        assert_eq!(
            admit(
                "reg.shop.checkout.c3",
                "10.0.0.3:8080",
                &d,
                &allow,
                None,
                Some(2)
            ),
            Err(Reject::ServiceQuota)
        );
        assert!(
            admit(
                "reg.shop.cart.a2",
                "10.0.0.8:8080",
                &d,
                &allow,
                None,
                Some(2)
            )
            .is_ok()
        );
    }

    #[test]
    fn key_helpers() {
        assert_eq!(service_prefix("reg.shop.checkout.c1"), "reg.shop.checkout");
        assert_eq!(identity_suffix("reg.shop.checkout.c1"), "shop.checkout.c1");
        assert_eq!(
            identity_suffix("override.shop.checkout.c1"),
            "shop.checkout.c1"
        );
    }
}
