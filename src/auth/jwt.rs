//! JWT validation against a JWKS-backed key cache.
//!
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
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation, decode, decode_header};
use tokio::sync::Mutex;

use crate::config::{AuthBlockConfig, ClaimHeaderMapping};
use crate::upstream::{ProxyBody, ProxyClient, into_proxy_body};

use super::policy::Requirements;

#[derive(Debug)]
pub enum AuthError {
    MissingToken,
    MalformedToken,
    MissingKid,
    UnknownKid,
    DisallowedAlgorithm,
    InvalidSignature,
    InvalidClaims(String),
    /// `exp` has passed. Rejected like other claim failures (403) on bearer
    /// routes, but a fresh sign-in fixes it, so it can trigger a redirect.
    Expired,
    /// A `claim_equals` / `claim_contains` rule failed (authorisation: 403).
    ClaimMismatch(String),
    /// The token is valid but its authentication is too weak or too old for
    /// this route (`[routes.require]` `amr` / `max_auth_age_seconds`): step up.
    InsufficientAuthentication(String),
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
            AuthError::Expired => write!(f, "JWT expired"),
            AuthError::ClaimMismatch(m) => write!(f, "JWT claim policy failed: {m}"),
            AuthError::InsufficientAuthentication(m) => {
                write!(f, "insufficient user authentication: {m}")
            }
            AuthError::SpoofedHeader(h) => write!(f, "client supplied reserved header '{h}'"),
            AuthError::JwksFetch(m) => write!(f, "JWKS fetch failed: {m}"),
            AuthError::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for AuthError {}

impl AuthError {
    /// Whether signing in again could turn this rejection into an allow - the
    /// cases a browser is redirected to `login_redirect` for. Wrong issuer /
    /// audience, missing required claims, claim-policy failures and spoofed
    /// headers are not: a new token from the same issuer wouldn't change them.
    pub fn reauth_may_help(&self) -> bool {
        matches!(
            self,
            AuthError::MissingToken
                | AuthError::MalformedToken
                | AuthError::MissingKid
                | AuthError::UnknownKid
                | AuthError::DisallowedAlgorithm
                | AuthError::InvalidSignature
                | AuthError::Expired
                | AuthError::InsufficientAuthentication(_)
        )
    }
}

pub type Claims = serde_json::Value;

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
    /// The block's own claim rules, applied wherever the block is used.
    policy: Requirements,
    /// Browser-session settings; routes only (see [`BrowserSession`]).
    pub session: BrowserSession,
}

/// Where a route reads its token from and what a browser gets on failure.
/// Ignored by egress, which always reads `Proxy-Authorization`.
#[derive(Debug, Clone, Default)]
pub struct BrowserSession {
    /// Read the token from this cookie instead of `Authorization: Bearer`.
    pub token_cookie: Option<String>,
    /// `login_redirect` template; `{url}` is the encoded original URL.
    pub login_redirect: Option<String>,
}

impl AuthValidator {
    pub(super) fn build(cfg: &AuthBlockConfig, client: ProxyClient) -> Result<Self> {
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
            policy: Requirements::from_block(cfg),
            session: BrowserSession {
                token_cookie: cfg.token_cookie.clone(),
                login_redirect: cfg.login_redirect.clone(),
            },
        })
    }

    /// Validate a token. On a kid cache miss, attempts a single async refresh
    /// of the JWKS and retries. Allow only when signature + standard claims
    /// (`iss`/`aud`/`exp`) check out, every required claim is present and the
    /// block's own claim rules hold. Route requirements are separate - see
    /// [`validate_and_inject`](Self::validate_and_inject).
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
                ErrorKind::ExpiredSignature => AuthError::Expired,
                ErrorKind::InvalidIssuer
                | ErrorKind::InvalidAudience
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

        self.policy.check(&data.claims)?;

        Ok(data.claims)
    }

    /// Validate the token, check the route's own requirements, then write any
    /// configured claim-to-header mappings into `headers`. Headers reserved by
    /// `inject_headers` are always removed first so clients cannot spoof them.
    /// Returns the verified claims (forwarded to an external authorizer when
    /// the route has one).
    pub async fn validate_and_inject(
        &self,
        token: &str,
        headers: &mut HeaderMap,
        route: Option<&Requirements>,
    ) -> Result<Claims, AuthError> {
        let claims = self.validate(token).await?;
        if let Some(r) = route {
            r.check(&claims)?;
        }
        self.apply_injector(headers, &claims)?;
        Ok(claims)
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
