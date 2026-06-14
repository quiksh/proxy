//! Egress allow/deny policy: host patterns + CIDR + DNS-aware evaluation.
//!
//! Semantics: first-match-wins over a list of rules. Each rule has an action
//! (allow/deny) plus a set of host patterns and CIDR ranges. A rule matches
//! if the request hits ANY of its hosts OR ANY of its CIDRs - that way a
//! single rule can express "this kind of destination", whether it's named
//! by domain or by address. If no rule matches, the policy's `default_action`
//! applies.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use ipnet::IpNet;

use crate::auth::{AuthRegistry, AuthValidator};
use crate::config::{EgressAction, EgressAuthConfig, EgressConfig, EgressRuleConfig};

/// Result of policy evaluation against a single CONNECT target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

impl From<EgressAction> for Decision {
    fn from(a: EgressAction) -> Self {
        match a {
            EgressAction::Allow => Decision::Allow,
            EgressAction::Deny => Decision::Deny,
        }
    }
}

#[derive(Debug, Clone)]
pub enum HostMatcher {
    /// Case-insensitive exact match.
    Exact(String),
    /// Wildcard subdomain: stored form ".example.com", matches anything
    /// ending in that suffix (so `api.example.com` matches but the bare
    /// `example.com` does not - same semantics as in `routing.rs`).
    WildcardSubdomain(String),
}

impl HostMatcher {
    pub fn matches(&self, host: &str) -> bool {
        match self {
            HostMatcher::Exact(s) => s.eq_ignore_ascii_case(host),
            HostMatcher::WildcardSubdomain(suffix) => {
                host.len() > suffix.len()
                    && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
            }
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        if let Some(rest) = raw.strip_prefix("*.") {
            if rest.is_empty() {
                bail!("host wildcard '*.' must be followed by a domain");
            }
            Ok(HostMatcher::WildcardSubdomain(format!(".{rest}")))
        } else if raw.contains('*') {
            bail!("only leading '*.' wildcards are supported in host '{raw}'")
        } else if raw.is_empty() {
            bail!("empty host pattern")
        } else {
            Ok(HostMatcher::Exact(raw.to_string()))
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub action: Decision,
    pub hosts: Vec<HostMatcher>,
    pub cidrs: Vec<IpNet>,
}

impl CompiledRule {
    fn matches(&self, host: &str, ips: &[IpAddr]) -> bool {
        self.hosts.iter().any(|h| h.matches(host))
            || ips
                .iter()
                .any(|ip| self.cidrs.iter().any(|net| net.contains(ip)))
    }
}

#[derive(Debug)]
pub struct EgressPolicy {
    rules: Vec<CompiledRule>,
    default: Decision,
    sni_enforce: bool,
    /// DNS lookups for hostname targets time out at this bound. Resolution
    /// failure is treated as "no IPs to check" - the policy still applies
    /// host rules + default action.
    pub dns_timeout: Duration,
    auth: Option<CompiledEgressAuth>,
}

/// Compiled form of `EgressAuthConfig` - resolved against the global
/// `AuthRegistry` at startup so the hot path doesn't do a lookup per
/// request.
pub enum CompiledEgressAuth {
    Jwt {
        validator: Arc<AuthValidator>,
        originator_claim: String,
    },
    BasicLogOnly {
        realm: String,
    },
}

impl std::fmt::Debug for CompiledEgressAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompiledEgressAuth::Jwt {
                originator_claim, ..
            } => f
                .debug_struct("Jwt")
                .field("originator_claim", originator_claim)
                .finish_non_exhaustive(),
            CompiledEgressAuth::BasicLogOnly { realm } => f
                .debug_struct("BasicLogOnly")
                .field("realm", realm)
                .finish(),
        }
    }
}

impl EgressPolicy {
    /// Build a policy *without* proxy auth. Useful for tests that don't
    /// need the AuthRegistry machinery.
    pub fn from_config(cfg: &EgressConfig) -> Result<Self> {
        if cfg.auth.is_some() {
            bail!(
                "egress config has [egress.auth] - use from_config_with_auth(cfg, &auth_registry)"
            );
        }
        Self::build(cfg, None)
    }

    /// Build a policy with proxy auth resolved against the given registry.
    /// JWT mode looks up the named `[[auth]]` block; basic_log_only mode
    /// doesn't need the registry but takes it uniformly for symmetry.
    pub fn from_config_with_auth(cfg: &EgressConfig, registry: &AuthRegistry) -> Result<Self> {
        let auth = match &cfg.auth {
            None => None,
            Some(EgressAuthConfig::Jwt {
                block,
                originator_claim,
            }) => {
                let validator = registry.get(block).ok_or_else(|| {
                    anyhow!("egress.auth references unknown [[auth]] block '{block}'")
                })?;
                Some(CompiledEgressAuth::Jwt {
                    validator,
                    originator_claim: originator_claim.clone(),
                })
            }
            Some(EgressAuthConfig::BasicLogOnly { realm }) => {
                Some(CompiledEgressAuth::BasicLogOnly {
                    realm: realm.clone(),
                })
            }
        };
        Self::build(cfg, auth)
    }

    fn build(cfg: &EgressConfig, auth: Option<CompiledEgressAuth>) -> Result<Self> {
        let mut rules = Vec::with_capacity(cfg.rules.len());
        for (i, r) in cfg.rules.iter().enumerate() {
            rules.push(compile_rule(r).with_context(|| format!("egress rule #{}", i + 1))?);
        }
        Ok(Self {
            rules,
            default: cfg.default_action.into(),
            sni_enforce: cfg.sni_enforce,
            dns_timeout: Duration::from_secs(2),
            auth,
        })
    }

    pub fn auth(&self) -> Option<&CompiledEgressAuth> {
        self.auth.as_ref()
    }

    pub fn default_decision(&self) -> Decision {
        self.default
    }

    pub fn sni_enforce(&self) -> bool {
        self.sni_enforce
    }

    /// Decide on a CONNECT target, given the (already-known) target host
    /// and (optionally pre-resolved) IPs.
    pub fn evaluate(&self, host: &str, ips: &[IpAddr]) -> Decision {
        for rule in &self.rules {
            if rule.matches(host, ips) {
                return rule.action;
            }
        }
        self.default
    }

    /// Resolve the host to IPs if it's a name (not an IP literal). Used by
    /// `evaluate` callers that want CIDR rules to also apply when a hostname
    /// is given. Bounded by `dns_timeout`; on failure or timeout, returns
    /// the empty list (host-only rules can still match).
    pub async fn resolve(&self, host: &str) -> Vec<IpAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return vec![ip];
        }
        let lookup = format!("{host}:0");
        match tokio::time::timeout(self.dns_timeout, tokio::net::lookup_host(lookup)).await {
            Ok(Ok(iter)) => iter.map(|sa| sa.ip()).collect(),
            _ => Vec::new(),
        }
    }
}

fn compile_rule(r: &EgressRuleConfig) -> Result<CompiledRule> {
    if r.hosts.is_empty() && r.cidrs.is_empty() {
        bail!("rule has no hosts and no cidrs - at least one must be set");
    }
    let mut hosts = Vec::with_capacity(r.hosts.len());
    for h in &r.hosts {
        hosts.push(HostMatcher::parse(h).with_context(|| format!("host '{h}'"))?);
    }
    let mut cidrs = Vec::with_capacity(r.cidrs.len());
    for c in &r.cidrs {
        // Accept bare IP literals as /32 (v4) or /128 (v6).
        let net: IpNet = if c.contains('/') {
            c.parse().with_context(|| format!("cidr '{c}'"))?
        } else {
            let ip: IpAddr = c.parse().with_context(|| format!("ip '{c}'"))?;
            match ip {
                IpAddr::V4(v4) => IpNet::V4(v4.into()),
                IpAddr::V6(v6) => IpNet::V6(v6.into()),
            }
        };
        cidrs.push(net);
    }
    Ok(CompiledRule {
        action: r.action.into(),
        hosts,
        cidrs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(action: EgressAction, hosts: &[&str], cidrs: &[&str]) -> EgressRuleConfig {
        EgressRuleConfig {
            action,
            hosts: hosts.iter().map(|s| s.to_string()).collect(),
            cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn policy(default: EgressAction, rules: Vec<EgressRuleConfig>) -> EgressPolicy {
        let cfg = EgressConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            default_action: default,
            sni_enforce: false,
            rules,
            auth: None,
        };
        EgressPolicy::from_config(&cfg).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn exact_host_match() {
        let p = policy(
            EgressAction::Deny,
            vec![rule(EgressAction::Allow, &["github.com"], &[])],
        );
        assert_eq!(p.evaluate("github.com", &[]), Decision::Allow);
        assert_eq!(p.evaluate("evil.com", &[]), Decision::Deny);
    }

    #[test]
    fn host_match_is_case_insensitive() {
        let p = policy(
            EgressAction::Deny,
            vec![rule(EgressAction::Allow, &["Example.COM"], &[])],
        );
        assert_eq!(p.evaluate("example.com", &[]), Decision::Allow);
        assert_eq!(p.evaluate("EXAMPLE.COM", &[]), Decision::Allow);
    }

    #[test]
    fn wildcard_subdomain_matches_subs_not_apex() {
        let p = policy(
            EgressAction::Deny,
            vec![rule(EgressAction::Allow, &["*.example.com"], &[])],
        );
        assert_eq!(p.evaluate("api.example.com", &[]), Decision::Allow);
        assert_eq!(p.evaluate("deep.api.example.com", &[]), Decision::Allow);
        assert_eq!(p.evaluate("example.com", &[]), Decision::Deny);
        assert_eq!(p.evaluate("evilexample.com", &[]), Decision::Deny);
    }

    #[test]
    fn cidr_against_ip_literal() {
        let p = policy(
            EgressAction::Deny,
            vec![rule(EgressAction::Allow, &[], &["10.0.0.0/8"])],
        );
        assert_eq!(p.evaluate("10.1.2.3", &[ip("10.1.2.3")]), Decision::Allow);
        assert_eq!(p.evaluate("11.1.2.3", &[ip("11.1.2.3")]), Decision::Deny);
    }

    #[test]
    fn cidr_against_resolved_hostname() {
        let p = policy(
            EgressAction::Allow,
            vec![rule(EgressAction::Deny, &[], &["169.254.0.0/16"])],
        );
        // Hostname resolves to a link-local IP - should be blocked even
        // though the host string didn't match anything.
        assert_eq!(
            p.evaluate("metadata.example", &[ip("169.254.169.254")]),
            Decision::Deny
        );
    }

    #[test]
    fn first_match_wins() {
        let p = policy(
            EgressAction::Deny,
            vec![
                rule(EgressAction::Allow, &["*.example.com"], &[]),
                rule(EgressAction::Deny, &["evil.example.com"], &[]),
            ],
        );
        // Allow rule comes first and matches - never get to the deny.
        assert_eq!(p.evaluate("evil.example.com", &[]), Decision::Allow);
    }

    #[test]
    fn ipv6_cidr() {
        let p = policy(
            EgressAction::Deny,
            vec![rule(EgressAction::Allow, &[], &["2001:db8::/32"])],
        );
        assert_eq!(
            p.evaluate("2001:db8::1", &[ip("2001:db8::1")]),
            Decision::Allow
        );
        assert_eq!(
            p.evaluate("2001:db9::1", &[ip("2001:db9::1")]),
            Decision::Deny
        );
    }

    #[test]
    fn bare_ip_as_cidr() {
        // CIDR field accepts bare IPs (treated as /32 or /128).
        let p = policy(
            EgressAction::Deny,
            vec![rule(EgressAction::Allow, &[], &["1.2.3.4"])],
        );
        assert_eq!(p.evaluate("1.2.3.4", &[ip("1.2.3.4")]), Decision::Allow);
        assert_eq!(p.evaluate("1.2.3.5", &[ip("1.2.3.5")]), Decision::Deny);
    }

    #[test]
    fn default_applies_when_no_rule_matches() {
        let p = policy(EgressAction::Allow, vec![]);
        assert_eq!(p.evaluate("anything.example", &[]), Decision::Allow);
    }

    #[test]
    fn empty_rule_rejected_at_compile() {
        let cfg = EgressConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            default_action: EgressAction::Deny,
            sni_enforce: false,
            rules: vec![rule(EgressAction::Allow, &[], &[])],
            auth: None,
        };
        let err = EgressPolicy::from_config(&cfg).unwrap_err();
        assert!(
            err.to_string().contains("no hosts and no cidrs")
                || err
                    .chain()
                    .any(|c| c.to_string().contains("no hosts and no cidrs")),
            "{err:?}"
        );
    }
}
