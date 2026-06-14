//! Route table: match an inbound request to a route entry.
//!
//! Precedence rules (applied via sort, then first-hit):
//! 1. Exact paths beat any prefix.
//! 2. Among prefixes, longest-prefix-first.
//! 3. Path matching is segment-aware - `/api` matches `/api` and `/api/x`,
//!    but NOT `/apifoo`.
//!
//! Host matching strips `:port` and is case-insensitive. Wildcard hosts use
//! the `*.example.com` form only (matches any subdomain, not the bare apex).
//!
//! [`SharedRoutingTable`] wraps the compiled table in an `ArcSwap` so a future
//! config reload can hot-swap routes without coordinating with in-flight
//! requests.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;
use http::Method;

use crate::config::{Config, RouteConfig};

/// What a route uses to decide whether a given request applies.
#[derive(Debug)]
pub struct RouteMatchers {
    /// Empty = match any host. Otherwise: at least one matcher must match.
    pub hosts: Vec<HostMatcher>,
    /// Empty = match any method. Otherwise: request method must be in the list.
    pub methods: Vec<Method>,
    /// Exactly one of `Exact(p)` or `Prefix(p)`.
    pub path: PathMatcher,
}

#[derive(Debug, Clone)]
pub enum HostMatcher {
    /// Case-insensitive exact match against the request Host / :authority host.
    Exact(String),
    /// `*.example.com` form: matches anything ending in `.example.com` (does
    /// not match the bare `example.com`).
    WildcardSubdomain(String),
}

impl HostMatcher {
    pub fn matches(&self, host: &str) -> bool {
        match self {
            HostMatcher::Exact(s) => host.eq_ignore_ascii_case(s),
            HostMatcher::WildcardSubdomain(suffix) => {
                // suffix already starts with '.' - store form: ".example.com"
                host.len() > suffix.len()
                    && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
            }
        }
    }

    fn parse(raw: &str) -> Result<Self> {
        if let Some(rest) = raw.strip_prefix("*.") {
            if rest.is_empty() {
                bail!("host wildcard '*.' must be followed by a domain");
            }
            Ok(HostMatcher::WildcardSubdomain(format!(".{rest}")))
        } else if raw.contains('*') {
            bail!("unsupported wildcard in host '{raw}' - only leading '*.' is allowed");
        } else if raw.is_empty() {
            bail!("empty host string");
        } else {
            Ok(HostMatcher::Exact(raw.to_string()))
        }
    }
}

#[derive(Debug, Clone)]
pub enum PathMatcher {
    /// Match exactly this path. Higher precedence than any prefix.
    Exact(String),
    /// Match this path segment-prefix (`/api` matches `/api`, `/api/x`, but not `/apifoo`).
    Prefix(String),
}

impl PathMatcher {
    pub fn matches(&self, path: &str) -> bool {
        match self {
            PathMatcher::Exact(p) => path == p,
            PathMatcher::Prefix(p) => is_segment_prefix(path, p),
        }
    }

    /// For sorting routes: more-specific matchers come first.
    fn specificity(&self) -> (u8, usize) {
        match self {
            // Exact paths always beat prefixes. Then longest first.
            PathMatcher::Exact(p) => (1, p.len()),
            PathMatcher::Prefix(p) => (0, p.len()),
        }
    }
}

/// `prefix` is a path-segment prefix of `path` iff `path == prefix` or
/// `path` continues with a '/' immediately after `prefix`. This avoids
/// `/api` accidentally matching `/apifoo`.
pub(crate) fn is_segment_prefix(path: &str, prefix: &str) -> bool {
    if !path.starts_with(prefix) {
        return false;
    }
    let after = &path[prefix.len()..];
    after.is_empty() || after.starts_with('/') || prefix.ends_with('/')
}

/// Per-route behavioural modules. Each field absent ⇒ that module is off.
#[derive(Debug, Default, Clone)]
pub struct RouteModules {
    /// Strip this prefix from the request path before forwarding upstream.
    /// If the request path doesn't start with this prefix, the path is left
    /// unchanged.
    pub strip_prefix: Option<String>,
    /// Upper bound on time the upstream has to respond. 504 on expiry.
    pub timeout_ms: Option<u64>,
    /// Maximum inbound request body size in bytes. Enforced via the
    /// `Content-Length` header. 413 if exceeded.
    pub max_body_bytes: Option<u64>,
}

#[derive(Debug)]
pub struct RouteEntry {
    pub matchers: RouteMatchers,
    pub modules: RouteModules,
    pub upstream_pool: String,
    /// Optional auth block name. None = route is anonymous.
    pub auth: Option<String>,
    pub label: Arc<str>,
}

impl RouteEntry {
    pub fn matches(&self, host: Option<&str>, method: &Method, path: &str) -> bool {
        if !self.matchers.methods.is_empty() && !self.matchers.methods.contains(method) {
            return false;
        }
        if !self.matchers.hosts.is_empty() {
            let h = match host {
                Some(h) => h,
                None => return false,
            };
            if !self.matchers.hosts.iter().any(|m| m.matches(h)) {
                return false;
            }
        }
        self.matchers.path.matches(path)
    }
}

#[derive(Debug)]
pub struct RoutingTable {
    routes: Vec<RouteEntry>,
}

impl RoutingTable {
    pub fn match_request(
        &self,
        host: Option<&str>,
        method: &Method,
        path: &str,
    ) -> Option<&RouteEntry> {
        // strip any ':port' from the Host header for matching purposes
        let host_no_port = host.map(|h| h.split(':').next().unwrap_or(h));
        self.routes
            .iter()
            .find(|r| r.matches(host_no_port, method, path))
    }

    pub fn from_routes(routes: &[RouteConfig]) -> Result<Self> {
        build_table(routes)
    }
}

pub struct SharedRoutingTable {
    inner: ArcSwap<RoutingTable>,
}

impl SharedRoutingTable {
    pub fn from_config(cfg: &Config) -> Result<Self> {
        let table = RoutingTable::from_routes(&cfg.routes)?;
        Ok(Self {
            inner: ArcSwap::from_pointee(table),
        })
    }

    pub fn load(&self) -> arc_swap::Guard<Arc<RoutingTable>> {
        self.inner.load()
    }

    #[allow(dead_code)]
    pub fn swap(&self, new: RoutingTable) {
        self.inner.store(Arc::new(new));
    }
}

fn build_table(routes: &[RouteConfig]) -> Result<RoutingTable> {
    let mut entries = Vec::with_capacity(routes.len());
    for r in routes {
        let hosts: Result<Vec<_>> = r
            .all_hosts()
            .iter()
            .map(|h| HostMatcher::parse(h))
            .collect();
        let hosts = hosts.with_context(|| format!("route '{}': host parse", r.summary()))?;

        let methods: Result<Vec<Method>> = r
            .all_methods()
            .iter()
            .map(|m| {
                m.parse::<Method>()
                    .with_context(|| format!("invalid HTTP method '{m}'"))
            })
            .collect();
        let methods = methods.with_context(|| format!("route '{}': method parse", r.summary()))?;

        let path = match (&r.path_exact, &r.path_prefix) {
            (Some(_), Some(_)) => bail!(
                "route '{}': set either path_exact or path_prefix, not both",
                r.summary()
            ),
            (Some(e), None) => {
                if !e.starts_with('/') {
                    bail!("route '{}': path_exact must start with '/'", r.summary());
                }
                PathMatcher::Exact(e.clone())
            }
            (None, Some(p)) => {
                if !p.starts_with('/') {
                    bail!("route '{}': path_prefix must start with '/'", r.summary());
                }
                PathMatcher::Prefix(p.clone())
            }
            (None, None) => PathMatcher::Prefix("/".to_string()),
        };

        let modules = RouteModules {
            strip_prefix: r.strip_prefix.clone(),
            timeout_ms: r.timeout_ms,
            max_body_bytes: r.max_body_bytes,
        };

        let label: Arc<str> = labelize(&methods, &hosts, &path).into();

        entries.push(RouteEntry {
            matchers: RouteMatchers {
                hosts,
                methods,
                path,
            },
            modules,
            upstream_pool: r.upstream.clone(),
            auth: r.auth.clone(),
            label,
        });
    }

    // Most specific first: exact paths beat prefixes, then longest-prefix-first.
    entries.sort_by_key(|e| std::cmp::Reverse(e.matchers.path.specificity()));
    Ok(RoutingTable { routes: entries })
}

fn labelize(methods: &[Method], hosts: &[HostMatcher], path: &PathMatcher) -> String {
    fn fmt_methods(m: &[Method]) -> String {
        match m {
            [] => "*".to_string(),
            [only] => only.to_string(),
            many => format!(
                "[{}]",
                many.iter()
                    .map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }
    }
    fn fmt_hosts(h: &[HostMatcher]) -> String {
        match h {
            [] => "*".to_string(),
            [only] => fmt_host(only),
            many => format!(
                "[{}]",
                many.iter().map(fmt_host).collect::<Vec<_>>().join(",")
            ),
        }
    }
    fn fmt_host(h: &HostMatcher) -> String {
        match h {
            HostMatcher::Exact(s) => s.clone(),
            HostMatcher::WildcardSubdomain(suffix) => format!("*{suffix}"),
        }
    }
    fn fmt_path(p: &PathMatcher) -> String {
        match p {
            PathMatcher::Exact(s) => format!("={s}"),
            PathMatcher::Prefix(s) => s.clone(),
        }
    }
    format!(
        "{} {}{}",
        fmt_methods(methods),
        fmt_hosts(hosts),
        fmt_path(path)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RouteConfig;

    #[derive(Default)]
    struct R<'a> {
        host: Option<&'a str>,
        hosts: Vec<&'a str>,
        method: Option<&'a str>,
        methods: Vec<&'a str>,
        path_prefix: Option<&'a str>,
        path_exact: Option<&'a str>,
        strip_prefix: Option<&'a str>,
        up: &'a str,
    }

    fn route(r: R) -> RouteConfig {
        RouteConfig {
            host: r.host.map(str::to_owned),
            hosts: r.hosts.into_iter().map(str::to_owned).collect(),
            method: r.method.map(str::to_owned),
            methods: r.methods.into_iter().map(str::to_owned).collect(),
            path_prefix: r.path_prefix.map(str::to_owned),
            path_exact: r.path_exact.map(str::to_owned),
            strip_prefix: r.strip_prefix.map(str::to_owned),
            timeout_ms: None,
            max_body_bytes: None,
            auth: None,
            upstream: r.up.to_owned(),
        }
    }

    fn tbl(routes: Vec<RouteConfig>) -> RoutingTable {
        build_table(&routes).unwrap()
    }

    #[test]
    fn longest_prefix_first() {
        let t = tbl(vec![
            route(R {
                path_prefix: Some("/"),
                up: "root",
                ..Default::default()
            }),
            route(R {
                path_prefix: Some("/api/users"),
                up: "users",
                ..Default::default()
            }),
            route(R {
                path_prefix: Some("/api"),
                up: "api",
                ..Default::default()
            }),
        ]);
        assert_eq!(
            &t.match_request(Some("h"), &Method::GET, "/api/users/42")
                .unwrap()
                .upstream_pool,
            "users"
        );
        assert_eq!(
            &t.match_request(Some("h"), &Method::GET, "/api/x")
                .unwrap()
                .upstream_pool,
            "api"
        );
        assert_eq!(
            &t.match_request(Some("h"), &Method::GET, "/other")
                .unwrap()
                .upstream_pool,
            "root"
        );
    }

    #[test]
    fn exact_path_beats_prefix() {
        let t = tbl(vec![
            route(R {
                path_prefix: Some("/api"),
                up: "api-prefix",
                ..Default::default()
            }),
            route(R {
                path_exact: Some("/api/healthz"),
                up: "health",
                ..Default::default()
            }),
        ]);
        assert_eq!(
            &t.match_request(Some("h"), &Method::GET, "/api/healthz")
                .unwrap()
                .upstream_pool,
            "health"
        );
        assert_eq!(
            &t.match_request(Some("h"), &Method::GET, "/api/anything")
                .unwrap()
                .upstream_pool,
            "api-prefix"
        );
    }

    #[test]
    fn segment_aware_prefix_does_not_match_substring() {
        let t = tbl(vec![route(R {
            path_prefix: Some("/api"),
            up: "api",
            ..Default::default()
        })]);
        assert!(
            t.match_request(Some("h"), &Method::GET, "/apifoo")
                .is_none()
        );
        assert!(t.match_request(Some("h"), &Method::GET, "/api/x").is_some());
        assert!(t.match_request(Some("h"), &Method::GET, "/api").is_some());
    }

    #[test]
    fn wildcard_subdomain_host_match() {
        let t = tbl(vec![route(R {
            hosts: vec!["*.example.com"],
            path_prefix: Some("/"),
            up: "any-example",
            ..Default::default()
        })]);
        assert!(
            t.match_request(Some("api.example.com"), &Method::GET, "/x")
                .is_some()
        );
        assert!(
            t.match_request(Some("a.b.example.com"), &Method::GET, "/x")
                .is_some()
        );
        // bare apex doesn't match
        assert!(
            t.match_request(Some("example.com"), &Method::GET, "/x")
                .is_none()
        );
        // sibling domain doesn't match
        assert!(
            t.match_request(Some("notexample.com"), &Method::GET, "/x")
                .is_none()
        );
    }

    #[test]
    fn multi_host_matches_any() {
        let t = tbl(vec![route(R {
            hosts: vec!["api.example.com", "api.internal"],
            path_prefix: Some("/"),
            up: "p",
            ..Default::default()
        })]);
        assert!(
            t.match_request(Some("api.example.com"), &Method::GET, "/x")
                .is_some()
        );
        assert!(
            t.match_request(Some("api.internal"), &Method::GET, "/x")
                .is_some()
        );
        assert!(t.match_request(Some("other"), &Method::GET, "/x").is_none());
    }

    #[test]
    fn multi_method_matches_any() {
        let t = tbl(vec![route(R {
            methods: vec!["GET", "POST"],
            path_prefix: Some("/op"),
            up: "p",
            ..Default::default()
        })]);
        assert!(t.match_request(Some("h"), &Method::GET, "/op").is_some());
        assert!(t.match_request(Some("h"), &Method::POST, "/op").is_some());
        assert!(t.match_request(Some("h"), &Method::PUT, "/op").is_none());
    }

    #[test]
    fn host_match_strips_port_and_ignores_case() {
        let t = tbl(vec![route(R {
            hosts: vec!["Api.Example.COM"],
            path_prefix: Some("/"),
            up: "p",
            ..Default::default()
        })]);
        assert!(
            t.match_request(Some("api.example.com:8443"), &Method::GET, "/x")
                .is_some()
        );
        assert!(
            t.match_request(Some("API.example.com"), &Method::GET, "/x")
                .is_some()
        );
    }

    #[test]
    fn singular_host_and_plural_hosts_combine() {
        let t = tbl(vec![route(R {
            host: Some("legacy.example.com"),
            hosts: vec!["new.example.com"],
            path_prefix: Some("/"),
            up: "p",
            ..Default::default()
        })]);
        assert!(
            t.match_request(Some("legacy.example.com"), &Method::GET, "/")
                .is_some()
        );
        assert!(
            t.match_request(Some("new.example.com"), &Method::GET, "/")
                .is_some()
        );
    }

    #[test]
    fn empty_hosts_matches_any_including_none() {
        let t = tbl(vec![route(R {
            path_prefix: Some("/"),
            up: "p",
            ..Default::default()
        })]);
        assert!(t.match_request(None, &Method::GET, "/x").is_some());
        assert!(
            t.match_request(Some("anything"), &Method::GET, "/x")
                .is_some()
        );
    }
}
