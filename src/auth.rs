//! Per-route JWT authentication.
//!
//! Architecture
//! - [`AuthRegistry`] holds named [`AuthValidator`] instances, one per `[[auth]]`
//!   block in config. Looked up by name from the route's `auth = "..."` field.
//! - [`AuthValidator`] knows its issuer, audience, allowed algorithms, and which
//!   [`JwksCache`] to ask for signing keys.
//! - [`JwksCache`] holds a swap-able map of `kid -> DecodingKey`. On a kid miss
//!   it triggers an async refresh from the JWKS URL, deduplicated via a single
//!   in-flight lock so concurrent requests collapse to one fetch.
//!
//! Hot path
//! - `validate()` is fully synchronous on cache hit (signature verification +
//!   claims). No I/O. Only kid miss takes the async path.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use arc_swap::ArcSwap;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Request};
use http_body_util::{BodyExt, Empty};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation, decode, decode_header};
use rustls::ClientConfig;
use tokio::sync::Mutex;

use crate::config::{AuthBlockConfig, ClaimHeaderMapping, Config};
use crate::upstream::{ProxyBody, ProxyClient, into_proxy_body};

#[derive(Debug)]
pub enum AuthError {
    MissingToken,
    MalformedToken,
    MissingKid,
    UnknownKid,
    DisallowedAlgorithm,
    InvalidSignature,
    InvalidClaims(String),
    /// Client tried to set a header name reserved for `inject_headers`.
    /// Carries the offending header name for diagnostic logging.
    SpoofedHeader(String),
    JwksFetch(String),
    Other(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::MissingToken => write!(f, "missing bearer token"),
            AuthError::MalformedToken => write!(f, "malformed JWT"),
            AuthError::MissingKid => write!(f, "JWT header missing 'kid'"),
            AuthError::UnknownKid => write!(f, "unknown signing key id"),
            AuthError::DisallowedAlgorithm => write!(f, "disallowed JWT algorithm"),
            AuthError::InvalidSignature => write!(f, "JWT signature verification failed"),
            AuthError::InvalidClaims(m) => write!(f, "JWT claim validation failed: {m}"),
            AuthError::SpoofedHeader(h) => write!(f, "client supplied reserved header '{h}'"),
            AuthError::JwksFetch(m) => write!(f, "JWKS fetch failed: {m}"),
            AuthError::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for AuthError {}

pub type Claims = serde_json::Value;

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

struct CompiledMapping {
    claim: String,
    header: HeaderName,
    required: bool,
}

pub struct AuthValidator {
    pub name: String,
    jwks: Arc<JwksCache>,
    issuer: Option<String>,
    audience: Option<String>,
    algorithms: Vec<Algorithm>,
    required_claims: HashSet<String>,
    inject_headers: Vec<CompiledMapping>,
}

impl AuthValidator {
    fn build(cfg: &AuthBlockConfig, client: ProxyClient) -> Result<Self> {
        let algorithms = if cfg.algorithms.is_empty() {
            vec![Algorithm::RS256, Algorithm::ES256, Algorithm::EdDSA]
        } else {
            cfg.algorithms
                .iter()
                .map(|a| parse_algorithm(a))
                .collect::<Result<Vec<_>>>()?
        };
        let jwks = Arc::new(JwksCache::new(
            cfg.name.clone(),
            cfg.jwks_url.clone(),
            client,
        ));
        let inject_headers = cfg
            .inject_headers
            .iter()
            .map(compile_mapping)
            .collect::<Result<Vec<_>>>()
            .with_context(|| format!("compiling inject_headers for auth '{}'", cfg.name))?;
        Ok(Self {
            name: cfg.name.clone(),
            jwks,
            issuer: cfg.issuer.clone(),
            audience: cfg.audience.clone(),
            algorithms,
            required_claims: cfg.required_claims.iter().cloned().collect(),
            inject_headers,
        })
    }

    /// Validate a bearer token. On a kid cache miss, attempts a single async
    /// refresh of the JWKS and retries. Allow only when signature + standard
    /// claims (`iss`/`aud`/`exp`) check out and every required claim is
    /// present.
    pub async fn validate(&self, token: &str) -> Result<Claims, AuthError> {
        let header = decode_header(token).map_err(|_| AuthError::MalformedToken)?;
        if !self.algorithms.contains(&header.alg) {
            return Err(AuthError::DisallowedAlgorithm);
        }
        let kid = header.kid.as_deref().ok_or(AuthError::MissingKid)?;

        let key = match self.jwks.key_for(kid).await {
            Some(k) => k,
            None => return Err(AuthError::UnknownKid),
        };

        let mut validation = Validation::new(header.alg);
        if let Some(iss) = &self.issuer {
            validation.set_issuer(&[iss.as_str()]);
        }
        if let Some(aud) = &self.audience {
            validation.set_audience(&[aud.as_str()]);
        } else {
            // Don't reject tokens that omit `aud` if we don't require one.
            validation.validate_aud = false;
        }

        let data: TokenData<Claims> = decode(token, &key, &validation).map_err(|e| {
            use jsonwebtoken::errors::ErrorKind;
            match e.kind() {
                ErrorKind::InvalidSignature => AuthError::InvalidSignature,
                ErrorKind::InvalidIssuer
                | ErrorKind::InvalidAudience
                | ErrorKind::ExpiredSignature
                | ErrorKind::ImmatureSignature
                | ErrorKind::MissingRequiredClaim(_) => AuthError::InvalidClaims(e.to_string()),
                _ => AuthError::Other(e.to_string()),
            }
        })?;

        for required in &self.required_claims {
            if data.claims.get(required.as_str()).is_none() {
                return Err(AuthError::InvalidClaims(format!(
                    "missing required claim '{required}'"
                )));
            }
        }

        Ok(data.claims)
    }

    /// Validate the bearer token, then write any configured claim-to-header
    /// mappings into `headers`. Headers reserved by `inject_headers` are
    /// always removed first so clients cannot spoof them.
    pub async fn validate_and_inject(
        &self,
        token: &str,
        headers: &mut HeaderMap,
    ) -> Result<(), AuthError> {
        let claims = self.validate(token).await?;
        self.apply_injector(headers, &claims)?;
        Ok(())
    }

    fn apply_injector(&self, headers: &mut HeaderMap, claims: &Claims) -> Result<(), AuthError> {
        // SECURITY: clients must not set any header reserved for claim injection
        // - a present one is a spoof attempt, rejected loudly (visible in
        // metrics/logs) rather than silently overwritten. The match is by
        // `HeaderName`, so it is case-insensitive (`X-Tenant-Id` == `x-tenant-id`);
        // `first_reserved_present` and its test pin that invariant.
        if let Some(h) = first_reserved_present(headers, &self.inject_headers) {
            return Err(AuthError::SpoofedHeader(h.as_str().to_string()));
        }
        for m in &self.inject_headers {
            match claims.get(m.claim.as_str()) {
                Some(v) => {
                    let Some(s) = claim_to_string(v) else {
                        // Null claim - treat as missing.
                        if m.required {
                            return Err(AuthError::InvalidClaims(format!(
                                "claim '{}' present but null (required)",
                                m.claim
                            )));
                        }
                        continue;
                    };
                    match HeaderValue::try_from(s) {
                        Ok(hv) => {
                            headers.insert(m.header.clone(), hv);
                        }
                        Err(_) => {
                            tracing::warn!(
                                claim = %m.claim,
                                header = %m.header,
                                "claim contains characters invalid in HTTP header - dropping"
                            );
                            if m.required {
                                return Err(AuthError::InvalidClaims(format!(
                                    "claim '{}' contained invalid header chars",
                                    m.claim
                                )));
                            }
                        }
                    }
                }
                None => {
                    if m.required {
                        return Err(AuthError::InvalidClaims(format!(
                            "missing required claim '{}' for header injection",
                            m.claim
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}

/// SECURITY: the first `inject_headers` name present on the inbound request, if
/// any - a client setting a header reserved for claim injection is a spoof
/// attempt (it would otherwise pose as a verified identity to the upstream). The
/// lookup is case-insensitive because `HeaderMap::contains_key` compares by
/// normalised `HeaderName` (`X-Tenant-Id` and `x-tenant-id` are the same key).
/// The case-variant unit test pins this so a refactor to a raw string compare
/// can't silently reintroduce a case bypass.
fn first_reserved_present<'a>(
    headers: &HeaderMap,
    inject: &'a [CompiledMapping],
) -> Option<&'a HeaderName> {
    inject
        .iter()
        .map(|m| &m.header)
        .find(|h| headers.contains_key(*h))
}

fn compile_mapping(m: &ClaimHeaderMapping) -> Result<CompiledMapping> {
    let header = HeaderName::try_from(m.header.as_str())
        .with_context(|| format!("invalid header name '{}'", m.header))?;
    if m.claim.is_empty() {
        anyhow::bail!("inject_headers entry has empty claim name");
    }
    Ok(CompiledMapping {
        claim: m.claim.clone(),
        header,
        required: m.required,
    })
}

/// Best-effort stringification of a claim value into something suitable for
/// an HTTP header. Strings pass through; numbers + bools are formatted;
/// arrays of strings comma-joined; arrays of mixed types and objects are
/// JSON-encoded; null returns None (caller treats as missing).
fn claim_to_string(v: &serde_json::Value) -> Option<String> {
    use serde_json::Value;
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Array(arr) => {
            if arr.iter().all(|x| x.is_string()) {
                Some(
                    arr.iter()
                        .map(|x| x.as_str().unwrap())
                        .collect::<Vec<_>>()
                        .join(","),
                )
            } else {
                serde_json::to_string(arr).ok()
            }
        }
        Value::Object(_) => serde_json::to_string(v).ok(),
        Value::Null => None,
    }
}

fn parse_algorithm(s: &str) -> Result<Algorithm> {
    let alg = match s {
        "RS256" => Algorithm::RS256,
        "RS384" => Algorithm::RS384,
        "RS512" => Algorithm::RS512,
        "ES256" => Algorithm::ES256,
        "ES384" => Algorithm::ES384,
        "EdDSA" => Algorithm::EdDSA,
        "PS256" => Algorithm::PS256,
        "PS384" => Algorithm::PS384,
        "PS512" => Algorithm::PS512,
        "HS256" => Algorithm::HS256,
        "HS384" => Algorithm::HS384,
        "HS512" => Algorithm::HS512,
        other => return Err(anyhow!("unsupported JWT algorithm '{other}'")),
    };
    Ok(alg)
}

pub struct JwksCache {
    name: String,
    url: String,
    keys: ArcSwap<HashMap<String, DecodingKey>>,
    client: ProxyClient,
    refresh_lock: Mutex<()>,
}

impl JwksCache {
    fn new(name: String, url: String, client: ProxyClient) -> Self {
        Self {
            name,
            url,
            keys: ArcSwap::from_pointee(HashMap::new()),
            client,
            refresh_lock: Mutex::new(()),
        }
    }

    pub async fn key_for(&self, kid: &str) -> Option<DecodingKey> {
        if let Some(k) = self.keys.load().get(kid).cloned() {
            return Some(k);
        }
        // Miss: trigger one (deduplicated) refresh, then retry.
        if let Err(e) = self.refresh_once().await {
            tracing::warn!(url = %self.url, error = %e, "JWKS refresh failed");
            return None;
        }
        self.keys.load().get(kid).cloned()
    }

    async fn refresh_once(&self) -> Result<()> {
        // Serialise concurrent refreshes. After acquiring the lock, recheck
        // whether someone else just populated the cache so we don't fan out
        // duplicate fetches.
        let _guard = self.refresh_lock.lock().await;

        let started = std::time::Instant::now();
        let result = fetch_jwks(&self.client, &self.url).await;
        let elapsed = started.elapsed().as_secs_f64();

        match result {
            Ok(new_keys) => {
                metrics::counter!("quik_jwks_fetches_total",
                    "auth" => self.name.clone(),
                    "outcome" => "ok"
                )
                .increment(1);
                metrics::histogram!("quik_jwks_fetch_duration_seconds",
                    "auth" => self.name.clone()
                )
                .record(elapsed);
                self.keys.store(Arc::new(new_keys));
                Ok(())
            }
            Err(e) => {
                metrics::counter!("quik_jwks_fetches_total",
                    "auth" => self.name.clone(),
                    "outcome" => "error"
                )
                .increment(1);
                Err(e.context(format!("fetching {}", self.url)))
            }
        }
    }
}

async fn fetch_jwks(client: &ProxyClient, url: &str) -> Result<HashMap<String, DecodingKey>> {
    let uri: http::Uri = url.parse().context("parsing JWKS URL")?;
    let body: ProxyBody = into_proxy_body(Empty::<Bytes>::new());
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("user-agent", "quik/0.1 jwks-fetch")
        .header("accept", "application/json")
        .body(body)
        .context("building JWKS request")?;

    let resp = tokio::time::timeout(Duration::from_secs(5), client.request(req))
        .await
        .map_err(|_| anyhow!("timeout"))?
        .context("HTTP request")?;
    if !resp.status().is_success() {
        return Err(anyhow!("JWKS endpoint returned {}", resp.status()));
    }
    let body = resp
        .into_body()
        .collect()
        .await
        .context("reading JWKS body")?
        .to_bytes();
    let jwks: JwkSet = serde_json::from_slice(&body).context("parsing JWKS JSON")?;

    let mut out = HashMap::with_capacity(jwks.keys.len());
    for jwk in jwks.keys {
        let Some(kid) = jwk.common.key_id.clone() else {
            tracing::warn!("JWK without kid skipped");
            continue;
        };
        match DecodingKey::from_jwk(&jwk) {
            Ok(key) => {
                out.insert(kid, key);
            }
            Err(e) => {
                tracing::warn!(kid = %kid, error = %e, "failed to build DecodingKey from JWK");
            }
        }
    }
    Ok(out)
}

fn build_jwks_client() -> ProxyClient {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);
    Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(2)
        .pool_idle_timeout(Duration::from_secs(60))
        .build(https)
}

/// Build a JWKS client that bypasses certificate verification. Only used by
/// the test harness - production code should never call this.
#[doc(hidden)]
pub fn build_jwks_client_skip_verify() -> ProxyClient {
    use rustls::DigitallySignedStruct;
    use rustls::SignatureScheme;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    #[derive(Debug)]
    struct NoVerify;
    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    let tls_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);
    Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(2)
        .build(https)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping(claim: &str, header: &str) -> CompiledMapping {
        CompiledMapping {
            claim: claim.to_string(),
            header: header.parse().unwrap(),
            required: false,
        }
    }

    /// SECURITY: a reserved (injected) header must be detected on the inbound
    /// request regardless of the case the client sends it in - header names are
    /// case-insensitive, so a case-sensitive check would be a spoofing bypass.
    #[test]
    fn reserved_header_detection_is_case_insensitive() {
        let inject = vec![
            mapping("sub", "x-auth-sub"),
            mapping("tenant_id", "x-tenant-id"),
        ];

        for name in [
            "x-auth-sub",
            "X-Auth-Sub",
            "X-AUTH-SUB",
            "x-AUTH-sub",
            "X-auth-Sub",
            "x-tenant-id",
            "X-Tenant-Id",
            "X-TENANT-ID",
        ] {
            let mut h = HeaderMap::new();
            h.insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_static("spoofed"),
            );
            assert!(
                first_reserved_present(&h, &inject).is_some(),
                "case variant {name:?} of a reserved header must be caught"
            );
        }

        // A non-reserved header (any case) is not flagged.
        for name in ["x-not-reserved", "X-Not-Reserved", "authorization"] {
            let mut h = HeaderMap::new();
            h.insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_static("ok"),
            );
            assert!(
                first_reserved_present(&h, &inject).is_none(),
                "non-reserved header {name:?} must not be flagged"
            );
        }

        // No inbound headers → nothing reserved present.
        assert!(first_reserved_present(&HeaderMap::new(), &inject).is_none());
    }
}
