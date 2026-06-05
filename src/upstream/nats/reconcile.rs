//! Pure reconciliation helpers for the NATS watcher.
//!
//! No async-nats types appear here, so the security-critical logic — the
//! registrable-address allow-list (H1) and the member caps (H2) — is unit
//! tested without a server. See `docs/service-registration.md` §Security.

use std::collections::HashSet;
use std::net::IpAddr;

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

/// The service subtree of a registration key — everything but the final
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

/// Why a registration was refused — the `quik_nats_registration_rejected_total`
/// reason label and the audit outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Address outside the pool's allow-list (H1).
    Address,
    /// Pool member cap reached (H2 backstop).
    PoolCap,
    /// Per-service instance quota reached (H2).
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

/// Decide whether a `reg` key carrying `addr` may be admitted, given the keys
/// already accepted this pass (the watcher's authoritative view of
/// `Nats`-sourced members), the allow-list, and the caps. Re-registration of an
/// already-accepted key never consumes a fresh slot. Pure — the H1/H2 gate.
pub fn admit(
    key: &str,
    addr: &str,
    accepted: &HashSet<String>,
    allow: &[String],
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

/// True if `addr`'s host is permitted by the allow-list. Entries are CIDRs
/// (`10.0.0.0/8`), bare IPs (`10.0.0.5`), or host-suffixes (`.svc.local` /
/// `svc.local`). An IP host matches CIDR/IP entries; a hostname host matches
/// suffix entries. An empty allow-list denies everything (fail-safe).
pub fn address_allowed(addr: &str, allow: &[String]) -> bool {
    let host = host_of(addr);
    let host_ip = host.parse::<IpAddr>().ok();
    allow.iter().any(|entry| match host_ip {
        Some(ip) => {
            if let Ok(net) = entry.parse::<IpNet>() {
                net.contains(&ip)
            } else if let Ok(eip) = entry.parse::<IpAddr>() {
                eip == ip
            } else {
                false
            }
        }
        None => {
            let suffix = entry.trim_start_matches('.');
            !suffix.is_empty() && (host == suffix || host.ends_with(&format!(".{suffix}")))
        }
    })
}

/// Extract the host from a `host:port`, handling IPv6 brackets.
fn host_of(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match addr.rsplit_once(':') {
        Some((h, _)) => h,
        None => addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a set of already-accepted keys.
    fn accepted(keys: &[&str]) -> HashSet<String> {
        keys.iter().map(|k| k.to_string()).collect()
    }

    #[test]
    fn cidr_allow_accepts_in_range_rejects_out() {
        let allow = vec!["10.0.0.0/8".to_string()];
        assert!(address_allowed("10.4.5.6:8080", &allow));
        assert!(!address_allowed("192.168.1.1:8080", &allow));
        // The classic SSRF target must be rejected by a 10/8 allow-list.
        assert!(!address_allowed("169.254.169.254:80", &allow));
    }

    #[test]
    fn bare_ip_and_ipv6_bracket() {
        let allow = vec!["10.0.0.5".to_string(), "fd00::/8".to_string()];
        assert!(address_allowed("10.0.0.5:9000", &allow));
        assert!(!address_allowed("10.0.0.6:9000", &allow));
        assert!(address_allowed("[fd00::1]:8080", &allow));
        assert!(!address_allowed("[fe80::1]:8080", &allow));
    }

    #[test]
    fn host_suffix_match() {
        let allow = vec![".svc.cluster.local".to_string()];
        assert!(address_allowed("checkout-1.svc.cluster.local:8080", &allow));
        assert!(address_allowed("svc.cluster.local:8080", &allow));
        assert!(!address_allowed("evil.example.com:8080", &allow));
        // A hostname must not be admitted by a CIDR-only allow-list.
        assert!(!address_allowed(
            "checkout.internal:8080",
            &["10.0.0.0/8".to_string()]
        ));
    }

    #[test]
    fn empty_allow_list_denies_all() {
        assert!(!address_allowed("10.0.0.1:8080", &[]));
    }

    #[test]
    fn admit_rejects_bad_address() {
        let err = admit(
            "reg.shop.checkout.c1",
            "169.254.169.254:80",
            &accepted(&[]),
            &["10.0.0.0/8".to_string()],
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(err, Reject::Address);
    }

    #[test]
    fn admit_enforces_pool_cap_but_allows_refresh() {
        let d = accepted(&["reg.shop.checkout.c1", "reg.shop.checkout.c2"]);
        let allow = vec!["10.0.0.0/8".to_string()];
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
        let allow = vec!["10.0.0.0/8".to_string()];
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
