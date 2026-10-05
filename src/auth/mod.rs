//! Per-route authentication.
//!
//! Architecture
//! - [`AuthRegistry`] holds named [`AuthValidator`] instances, one per `[[auth]]`
//!   block in config. Looked up by name from the route's `auth = "..."` field.
//! - [`jwt`]: [`AuthValidator`] (JWT signature + claims checks, claim-to-header
//!   injection) and [`JwksCache`] (lazily-refreshed signing keys).
//! - [`authorizer`]: [`HttpAuthorizer`], an external HTTP service consulted
//!   per request (`[[authorizers]]`, route field `authorizer = "..."`).
//! - [`client`]: outbound HTTP clients for JWKS fetches and authorizers.
//! - [`policy`]: claim rules and step-up checks ([`policy::Requirements`]),
//!   for both `[[auth]]` blocks and `[routes.require]`.
//! - [`session`]: browser sessions - token-from-cookie, stripping the session
//!   cookie before forwarding, and login redirects for page loads.

mod authorizer;
mod cache;
mod client;
mod jwt;
pub mod policy;
pub mod session;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;

use crate::config::{AuthorizerTlsConfig, Config};
use crate::upstream::ProxyClient;

pub use authorizer::{AuthzRequest, AuthzVerdict, HttpAuthorizer};
pub use client::build_jwks_client_skip_verify;
pub use jwt::{AuthError, AuthValidator, BrowserSession, Claims, JwksCache};

use client::{build_authorizer_client, build_jwks_client};

pub struct AuthRegistry {
    validators: HashMap<String, Arc<AuthValidator>>,
    authorizers: HashMap<String, Arc<HttpAuthorizer>>,
}

impl AuthRegistry {
    pub fn empty() -> Self {
        Self {
            validators: HashMap::new(),
            authorizers: HashMap::new(),
        }
    }

    pub fn from_config(cfg: &Config) -> Result<Self> {
        Self::build_with_clients(cfg, build_jwks_client(), build_authorizer_client)
    }

    /// Test-only variant that builds JWKS and authorizer clients with
    /// certificate verification disabled (authorizer `tls` settings are
    /// ignored). Used by the integration test harness which spawns its own
    /// self-signed (or plain-HTTP) JWKS and authorizer servers.
    #[doc(hidden)]
    pub fn from_config_for_tests(cfg: &Config) -> Result<Self> {
        Self::build_with_clients(cfg, build_jwks_client_skip_verify(), |_| {
            Ok(build_jwks_client_skip_verify())
        })
    }

    fn build_with_clients(
        cfg: &Config,
        jwks_client: ProxyClient,
        authorizer_client: fn(&AuthorizerTlsConfig) -> Result<ProxyClient>,
    ) -> Result<Self> {
        let mut validators = HashMap::with_capacity(cfg.auth.len());
        for a in &cfg.auth {
            let v = AuthValidator::build(a, jwks_client.clone())
                .with_context(|| format!("building auth '{}'", a.name))?;
            validators.insert(a.name.clone(), Arc::new(v));
        }
        let mut authorizers = HashMap::with_capacity(cfg.authorizers.len());
        for z in &cfg.authorizers {
            let client = authorizer_client(&z.tls)
                .with_context(|| format!("building client for authorizer '{}'", z.name))?;
            let a = HttpAuthorizer::build(z, client)
                .with_context(|| format!("building authorizer '{}'", z.name))?;
            authorizers.insert(z.name.clone(), Arc::new(a));
        }
        Ok(Self {
            validators,
            authorizers,
        })
    }

    pub fn get(&self, name: &str) -> Option<Arc<AuthValidator>> {
        self.validators.get(name).cloned()
    }

    pub fn get_authorizer(&self, name: &str) -> Option<Arc<HttpAuthorizer>> {
        self.authorizers.get(name).cloned()
    }
}

/// An [`AuthRegistry`] behind an [`ArcSwap`] so a config reload can replace the
/// set of `[[auth]]` validators atomically. Readers (the proxy hot path) take a
/// single lock-free load per lookup. Mirrors
/// [`crate::routing::SharedRoutingTable`].
///
/// A swapped-in registry carries fresh, empty [`JwksCache`]s: the first request
/// per `kid` after a reload re-fetches the JWKS. In-flight validations holding
/// an `Arc<AuthValidator>` from the previous registry complete unaffected.
pub struct SharedAuthRegistry {
    inner: ArcSwap<AuthRegistry>,
}

impl SharedAuthRegistry {
    pub fn new(registry: AuthRegistry) -> Self {
        Self {
            inner: ArcSwap::from_pointee(registry),
        }
    }

    pub fn from_config(cfg: &Config) -> Result<Self> {
        Ok(Self::new(AuthRegistry::from_config(cfg)?))
    }

    /// Test-only: build validators whose JWKS clients skip certificate
    /// verification. See [`AuthRegistry::from_config_for_tests`].
    #[doc(hidden)]
    pub fn from_config_for_tests(cfg: &Config) -> Result<Self> {
        Ok(Self::new(AuthRegistry::from_config_for_tests(cfg)?))
    }

    /// Resolve a validator by name (single lock-free load + Arc clone).
    pub fn get(&self, name: &str) -> Option<Arc<AuthValidator>> {
        self.inner.load().get(name)
    }

    /// Resolve an authorizer by name (single lock-free load + Arc clone).
    pub fn get_authorizer(&self, name: &str) -> Option<Arc<HttpAuthorizer>> {
        self.inner.load().get_authorizer(name)
    }

    /// Borrow the current registry as an `Arc`. Used at startup to seed the
    /// egress policy, which holds its own boot-time validator clones.
    pub fn snapshot(&self) -> Arc<AuthRegistry> {
        self.inner.load_full()
    }

    /// Atomically replace the registry. Called by the config-reload path.
    pub fn swap(&self, registry: AuthRegistry) {
        self.inner.store(Arc::new(registry));
    }
}

/// Extract a bearer token from the `Authorization` header. Returns None if
/// the header is missing or doesn't start with `Bearer `.
pub fn extract_bearer_token(headers: &http::HeaderMap) -> Option<&str> {
    let v = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    let token = v
        .strip_prefix("Bearer ")
        .or_else(|| v.strip_prefix("bearer "))?;
    if token.is_empty() {
        return None;
    }
    Some(token)
}
