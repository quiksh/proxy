//! Per-route authentication.
//!
//! Architecture
//! - [`AuthRegistry`] holds named [`AuthValidator`] instances, one per `[[auth]]`
//!   block in config. Looked up by name from the route's `auth = "..."` field.
//! - [`jwt`]: [`AuthValidator`] (JWT signature + claims checks, claim-to-header
//!   injection) and [`JwksCache`] (lazily-refreshed signing keys).
//! - [`client`]: the outbound HTTP client used to fetch JWKS documents.

mod client;
mod jwt;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;

use crate::config::Config;
use crate::upstream::ProxyClient;

pub use client::build_jwks_client_skip_verify;
pub use jwt::{AuthError, AuthValidator, Claims, JwksCache};

use client::build_jwks_client;

pub struct AuthRegistry {
    validators: HashMap<String, Arc<AuthValidator>>,
}

impl AuthRegistry {
    pub fn empty() -> Self {
        Self {
            validators: HashMap::new(),
        }
    }

    pub fn from_config(cfg: &Config) -> Result<Self> {
        let client = build_jwks_client();
        Self::build_with_client(cfg, client)
    }

    /// Test-only variant that builds JWKS clients with certificate
    /// verification disabled. Used by the integration test harness which
    /// spawns its own self-signed (or plain-HTTP) JWKS server.
    #[doc(hidden)]
    pub fn from_config_for_tests(cfg: &Config) -> Result<Self> {
        let client = build_jwks_client_skip_verify();
        Self::build_with_client(cfg, client)
    }

    fn build_with_client(cfg: &Config, client: ProxyClient) -> Result<Self> {
        let mut validators = HashMap::with_capacity(cfg.auth.len());
        for a in &cfg.auth {
            let v = AuthValidator::build(a, client.clone())
                .with_context(|| format!("building auth '{}'", a.name))?;
            validators.insert(a.name.clone(), Arc::new(v));
        }
        Ok(Self { validators })
    }

    pub fn get(&self, name: &str) -> Option<Arc<AuthValidator>> {
        self.validators.get(name).cloned()
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
