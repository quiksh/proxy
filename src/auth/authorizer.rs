//! External HTTP authorizer (`[[authorizers]]`).
//!
//! Per request on a route with `authorizer = "name"`, quik POSTs a JSON
//! envelope describing the request to the configured URL and lets the
//! response status decide:
//!
//! - **2xx** - allow. An optional JSON body `{"headers": {"name": "value"}}`
//!   names headers to set on the upstream-bound request; only names in the
//!   block's `inject_headers` allowlist are applied (others are dropped and
//!   logged). An empty body (e.g. 204) is a plain allow.
//! - **4xx** - deny. The status, body, and `content-type` /
//!   `www-authenticate` headers are relayed to the client.
//! - **anything else** (3xx, 5xx, timeout, connect error, malformed 2xx body)
//!   - the authorizer gave no verdict; the caller applies `on_error`.
//!
//! The authorizer client keeps pooled keep-alive connections, so the steady
//! state cost is one round trip on a warm connection.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use http::header::{CONTENT_TYPE, USER_AGENT, WWW_AUTHENTICATE};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full, Limited};
use serde::{Deserialize, Serialize};

use super::Claims;
use crate::config::{AuthorizerConfig, AuthorizerOnError};
use crate::upstream::{ProxyClient, into_proxy_body};

/// Cap on the authorizer's response body (allow or deny). A larger response
/// is treated as an authorizer error rather than buffered.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Envelope schema version, sent as `version` so the wire format can evolve.
const ENVELOPE_VERSION: &str = "1";

pub struct HttpAuthorizer {
    pub name: String,
    pub on_error: AuthorizerOnError,
    uri: Uri,
    timeout: Duration,
    forward_headers: Vec<HeaderName>,
    inject_headers: Vec<HeaderName>,
    client: ProxyClient,
}

/// What the authorizer sees of the inbound request.
pub struct AuthzRequest<'a> {
    pub method: &'a Method,
    pub uri: &'a Uri,
    pub headers: &'a HeaderMap,
    pub source_ip: IpAddr,
    pub route: &'a str,
    pub request_id: &'a str,
    /// Verified JWT claims, when the route also has an `auth` block.
    pub claims: Option<&'a Claims>,
}

#[derive(Debug)]
pub enum AuthzVerdict {
    /// Allowed; set these headers on the upstream-bound request.
    Allow(Vec<(HeaderName, HeaderValue)>),
    /// Denied; relay this response to the client.
    Deny {
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
    },
}

#[derive(Serialize)]
struct Envelope<'a> {
    version: &'static str,
    request_id: &'a str,
    route: &'a str,
    source_ip: IpAddr,
    method: &'a str,
    host: Option<&'a str>,
    path: &'a str,
    query: Option<&'a str>,
    headers: BTreeMap<&'a str, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claims: Option<&'a Claims>,
}

#[derive(Deserialize)]
struct AllowBody {
    #[serde(default)]
    headers: HashMap<String, String>,
}

impl HttpAuthorizer {
    pub(super) fn build(cfg: &AuthorizerConfig, client: ProxyClient) -> Result<Self> {
        let parse_names = |names: &[String]| -> Result<Vec<HeaderName>> {
            names
                .iter()
                .map(|h| HeaderName::try_from(h.as_str()).with_context(|| format!("header '{h}'")))
                .collect()
        };
        Ok(Self {
            name: cfg.name.clone(),
            on_error: cfg.on_error,
            uri: cfg.url.parse().context("parsing authorizer url")?,
            timeout: Duration::from_millis(cfg.timeout_ms),
            forward_headers: parse_names(&cfg.forward_headers)?,
            inject_headers: parse_names(&cfg.inject_headers)?,
            client,
        })
    }

    /// SECURITY: the first `inject_headers` name present on the inbound
    /// request, if any. A client setting a header the authorizer is allowed to
    /// inject is a spoof attempt; the caller rejects it before calling out.
    /// `HeaderMap::contains_key` compares normalised names, so this is
    /// case-insensitive.
    pub fn reserved_present(&self, headers: &HeaderMap) -> Option<&HeaderName> {
        self.inject_headers
            .iter()
            .find(|h| headers.contains_key(*h))
    }

    /// Ask the authorizer for a verdict. `Err` means no verdict (timeout,
    /// transport failure, unexpected status, malformed body) - the caller
    /// applies `on_error`.
    pub async fn authorize(&self, req: AuthzRequest<'_>) -> Result<AuthzVerdict> {
        let started = Instant::now();
        let result = tokio::time::timeout(self.timeout, self.call(req))
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("timed out after {:?}", self.timeout)));
        metrics::histogram!("quik_authorizer_duration_seconds", "authorizer" => self.name.clone())
            .record(started.elapsed().as_secs_f64());
        result
    }

    async fn call(&self, req: AuthzRequest<'_>) -> Result<AuthzVerdict> {
        let body = serde_json::to_vec(&self.envelope(&req)).context("encoding envelope")?;
        let out = Request::post(self.uri.clone())
            .header(CONTENT_TYPE, "application/json")
            .header(USER_AGENT, "quik-authorizer")
            .body(into_proxy_body(Full::new(Bytes::from(body))))
            .context("building authorizer request")?;
        let resp = self
            .client
            .request(out)
            .await
            .context("authorizer request")?;
        let status = resp.status();

        if status.is_success() {
            let body = read_capped(resp.into_body()).await?;
            return Ok(AuthzVerdict::Allow(self.allowed_headers(&body)?));
        }
        if status.is_client_error() {
            let (parts, body) = resp.into_parts();
            let mut headers = HeaderMap::new();
            for name in [CONTENT_TYPE, WWW_AUTHENTICATE] {
                for v in parts.headers.get_all(&name) {
                    headers.append(name.clone(), v.clone());
                }
            }
            // An oversize deny body is dropped rather than turning a clear
            // deny into an authorizer error.
            let body = read_capped(body).await.unwrap_or_else(|_| {
                headers.remove(CONTENT_TYPE);
                Bytes::new()
            });
            return Ok(AuthzVerdict::Deny {
                status,
                headers,
                body,
            });
        }
        anyhow::bail!("authorizer returned {status}")
    }

    fn envelope<'a>(&'a self, req: &'a AuthzRequest<'a>) -> Envelope<'a> {
        let mut headers = BTreeMap::new();
        for name in &self.forward_headers {
            let values: Vec<&str> = req
                .headers
                .get_all(name)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect();
            if !values.is_empty() {
                headers.insert(name.as_str(), values.join(", "));
            }
        }
        let host = req
            .headers
            .get(http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .or_else(|| req.uri.authority().map(|a| a.as_str()));
        Envelope {
            version: ENVELOPE_VERSION,
            request_id: req.request_id,
            route: req.route,
            source_ip: req.source_ip,
            method: req.method.as_str(),
            host,
            path: req.uri.path(),
            query: req.uri.query(),
            headers,
            claims: req.claims,
        }
    }

    /// Parse an allow body into the headers to inject, keeping only
    /// allowlisted names. An invalid value on an allowlisted header is an
    /// error (fail closed) rather than a silent drop.
    fn allowed_headers(&self, body: &[u8]) -> Result<Vec<(HeaderName, HeaderValue)>> {
        if body.iter().all(u8::is_ascii_whitespace) {
            return Ok(Vec::new());
        }
        let parsed: AllowBody =
            serde_json::from_slice(body).context("authorizer allow body is not valid JSON")?;
        let mut out = Vec::with_capacity(parsed.headers.len());
        for (name, value) in parsed.headers {
            let allowed = HeaderName::try_from(name.as_str())
                .ok()
                .filter(|n| self.inject_headers.contains(n));
            let Some(header) = allowed else {
                tracing::warn!(
                    authorizer = %self.name,
                    header = %name,
                    "authorizer returned header not in inject_headers - dropping"
                );
                continue;
            };
            let value = HeaderValue::try_from(value)
                .with_context(|| format!("invalid value for header '{header}'"))?;
            out.push((header, value));
        }
        Ok(out)
    }
}

async fn read_capped<B>(body: B) -> Result<Bytes>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    Limited::new(body, MAX_RESPONSE_BYTES)
        .collect()
        .await
        .map(|c| c.to_bytes())
        .map_err(|e| anyhow::anyhow!("reading authorizer response: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorizer(inject: &[&str]) -> HttpAuthorizer {
        let cfg = AuthorizerConfig {
            name: "t".into(),
            url: "http://127.0.0.1:1/".into(),
            timeout_ms: 100,
            forward_headers: vec!["authorization".into()],
            inject_headers: inject.iter().map(|s| s.to_string()).collect(),
            on_error: AuthorizerOnError::Deny,
            tls: Default::default(),
        };
        HttpAuthorizer::build(&cfg, super::super::client::build_jwks_client_skip_verify()).unwrap()
    }

    #[test]
    fn empty_allow_body_injects_nothing() {
        let a = authorizer(&["x-user-id"]);
        assert!(a.allowed_headers(b"").unwrap().is_empty());
        assert!(a.allowed_headers(b" \n").unwrap().is_empty());
    }

    #[test]
    fn allow_body_filters_to_allowlist_case_insensitively() {
        let a = authorizer(&["x-user-id"]);
        let got = a
            .allowed_headers(br#"{"headers":{"X-User-Id":"u1","host":"evil","x-other":"z"}}"#)
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "x-user-id");
        assert_eq!(got[0].1, "u1");
    }

    #[test]
    fn malformed_allow_body_is_an_error() {
        let a = authorizer(&["x-user-id"]);
        assert!(a.allowed_headers(b"not json").is_err());
        assert!(
            a.allowed_headers(br#"{"headers":{"x-user-id":5}}"#)
                .is_err()
        );
        assert!(
            a.allowed_headers(br#"{"headers":{"x-user-id":"bad\nvalue"}}"#)
                .is_err()
        );
    }

    /// SECURITY: reserved-header detection must ignore case, or a client could
    /// spoof an injected identity header by changing its case.
    #[test]
    fn reserved_header_detection_is_case_insensitive() {
        let a = authorizer(&["x-tenant-id"]);
        for name in ["x-tenant-id", "X-Tenant-Id", "X-TENANT-ID"] {
            let mut h = HeaderMap::new();
            h.insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_static("spoofed"),
            );
            assert!(a.reserved_present(&h).is_some(), "{name} must be caught");
        }
        assert!(a.reserved_present(&HeaderMap::new()).is_none());
    }

    #[test]
    fn envelope_carries_only_forwarded_headers() {
        let a = authorizer(&[]);
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer t"));
        headers.insert("cookie", HeaderValue::from_static("secret=1"));
        headers.insert("host", HeaderValue::from_static("api.example.com"));
        let uri: Uri = "/v1/orders?limit=5".parse().unwrap();
        let req = AuthzRequest {
            method: &Method::POST,
            uri: &uri,
            headers: &headers,
            source_ip: "10.0.0.1".parse().unwrap(),
            route: "/v1",
            request_id: "rid",
            claims: None,
        };
        let v = serde_json::to_value(a.envelope(&req)).unwrap();
        assert_eq!(v["method"], "POST");
        assert_eq!(v["host"], "api.example.com");
        assert_eq!(v["path"], "/v1/orders");
        assert_eq!(v["query"], "limit=5");
        assert_eq!(v["source_ip"], "10.0.0.1");
        assert_eq!(v["headers"]["authorization"], "Bearer t");
        assert!(v["headers"].get("cookie").is_none());
        assert!(v.get("claims").is_none());
    }
}
