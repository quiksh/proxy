//! Mock external authorizer for local validation and integration testing of
//! quik's `[[authorizers]]` blocks. Speaks the same contract a real authorizer
//! must (see docs/config-reference.md#authorizers), driven by a small TOML
//! rules file so you can script allow / deny / error / slow responses without
//! writing a service.
//!
//! ```bash
//! cargo run --example mock_authorizer                         # built-in rules
//! AUTHZ_RULES=config/mock-authorizer.toml cargo run --example mock_authorizer
//! ```
//!
//! Endpoints:
//!   POST <any path>         - the authorizer. Evaluates rules, first match wins.
//!   GET  /_mock/requests    - envelopes received so far (newest last, max 100).
//!   DELETE /_mock/requests  - clear the recorded envelopes.
//!   GET  /healthz           - 200 "ok".
//!
//! Control headers (honoured before any rule, so integration tests can force a
//! path per request - list them in the authorizer's `forward_headers`):
//!   x-mock-status: <code>     respond with this status (e.g. 503 to test on_error)
//!   x-mock-delay-ms: <ms>     sleep before responding (e.g. to test timeout_ms)
//!
//! Environment:
//!   BIND_ADDR    (default: 127.0.0.1:9100)
//!   AUTHZ_RULES  (default: built-in rules, printed at startup)

use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperServer;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;

const MAX_RECORDED: usize = 100;

const DEFAULT_RULES: &str = r#"
# Built-in rules. Override with AUTHZ_RULES=<path>. First match wins.

# A JWT verified by quik's [[auth]] block: pass the subject through.
[[rules]]
name    = "jwt subject"
claims  = { sub = "*" }
inject  = { "x-user-id" = "{claims.sub}" }

# A static dev API key.
[[rules]]
name    = "dev api key"
headers = { "x-api-key" = "dev-key" }
inject  = { "x-user-id" = "dev-user", "x-tenant-id" = "dev-tenant" }

# Bearer tokens of the form `allow-<user>` are allowed as <user>.
[[rules]]
name         = "allow-<user> bearer"
bearer_prefix = "allow-"
inject       = { "x-user-id" = "{bearer_suffix}" }

[default]
name             = "deny"
status           = 401
body             = '{"message":"unauthorised"}'
www_authenticate = 'Bearer realm="mock"'
"#;

#[derive(Debug, Deserialize)]
struct RulesFile {
    #[serde(default)]
    rules: Vec<Rule>,
    default: Outcome,
}

#[derive(Debug, Deserialize)]
struct Rule {
    // ── matchers (all set ones must match) ──
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    path_prefix: Option<String>,
    /// Header name → exact value, or "*" for "present".
    #[serde(default)]
    headers: BTreeMap<String, String>,
    /// Top-level claim → exact string value, or "*" for "present".
    #[serde(default)]
    claims: BTreeMap<String, String>,
    /// Bearer token in `authorization` starts with this prefix.
    #[serde(default)]
    bearer_prefix: Option<String>,
    /// Decoded request body contains this substring (needs `include_body`).
    #[serde(default)]
    body_contains: Option<String>,
    #[serde(flatten)]
    outcome: Outcome,
}

#[derive(Debug, Deserialize)]
struct Outcome {
    #[serde(default)]
    name: Option<String>,
    #[serde(default = "default_status")]
    status: u16,
    /// Headers to ask quik to inject (2xx only). Values support
    /// `{claims.X}`, `{header.X}`, `{bearer_suffix}`, `{method}`, `{path}`.
    #[serde(default)]
    inject: BTreeMap<String, String>,
    /// Response body for non-2xx responses.
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    www_authenticate: Option<String>,
    /// `Cache-Control` on the response, e.g. "no-store" or "max-age=30", to
    /// exercise quik's `[authorizers.cache]`.
    #[serde(default)]
    cache_control: Option<String>,
    #[serde(default)]
    delay_ms: u64,
}

fn default_status() -> u16 {
    200
}

struct State {
    rules: RulesFile,
    recorded: Mutex<VecDeque<Value>>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let bind: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9100".to_string())
        .parse()
        .context("parsing BIND_ADDR")?;
    let (source, text) = match std::env::var("AUTHZ_RULES") {
        Ok(path) => {
            let text = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
            (path, text)
        }
        Err(_) => ("built-in".to_string(), DEFAULT_RULES.to_string()),
    };
    let rules: RulesFile = toml::from_str(&text).with_context(|| format!("parsing {source}"))?;
    if source == "built-in" {
        eprintln!("{DEFAULT_RULES}");
    }
    let state = Arc::new(State {
        rules,
        recorded: Mutex::new(VecDeque::new()),
    });

    let listener = TcpListener::bind(bind).await.context("binding listener")?;
    eprintln!(
        "mock_authorizer listening on {bind} ({} rules from {source})",
        state.rules.rules.len()
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let state = state.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(route(req, &state).await) }
            });
            if let Err(e) = HyperServer::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), svc)
                .await
            {
                eprintln!("conn error from {peer}: {e}");
            }
        });
    }
}

async fn route(req: Request<Incoming>, state: &State) -> Response<Full<Bytes>> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/healthz") => text(StatusCode::OK, "ok\n"),
        (&Method::GET, "/_mock/requests") => {
            let recorded: Vec<Value> = state.recorded.lock().unwrap().iter().cloned().collect();
            json_response(StatusCode::OK, &Value::Array(recorded))
        }
        (&Method::DELETE, "/_mock/requests") => {
            state.recorded.lock().unwrap().clear();
            text(StatusCode::NO_CONTENT, "")
        }
        (&Method::POST, _) => authorize(req, state).await,
        _ => text(StatusCode::METHOD_NOT_ALLOWED, "POST the envelope\n"),
    }
}

async fn authorize(req: Request<Incoming>, state: &State) -> Response<Full<Bytes>> {
    let body = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => return text(StatusCode::BAD_REQUEST, &format!("read error: {e}\n")),
    };
    let env: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return text(StatusCode::BAD_REQUEST, &format!("bad envelope: {e}\n")),
    };
    {
        let mut rec = state.recorded.lock().unwrap();
        if rec.len() == MAX_RECORDED {
            rec.pop_front();
        }
        rec.push_back(env.clone());
    }

    // Control headers first.
    if let Some(ms) = header(&env, "x-mock-delay-ms").and_then(|v| v.parse().ok()) {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
    if let Some(code) = header(&env, "x-mock-status").and_then(|v| v.parse::<u16>().ok()) {
        log(&env, "x-mock-status", code);
        return text(
            StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            "forced by x-mock-status\n",
        );
    }

    let outcome = state
        .rules
        .rules
        .iter()
        .find(|r| r.matches(&env))
        .map(|r| &r.outcome)
        .unwrap_or(&state.rules.default);
    if outcome.delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(outcome.delay_ms)).await;
    }
    log(
        &env,
        outcome.name.as_deref().unwrap_or("unnamed"),
        outcome.status,
    );
    outcome.respond(&env)
}

impl Rule {
    fn matches(&self, env: &Value) -> bool {
        if let Some(m) = &self.method
            && !env["method"]
                .as_str()
                .is_some_and(|x| x.eq_ignore_ascii_case(m))
        {
            return false;
        }
        if let Some(p) = &self.path_prefix
            && !env["path"]
                .as_str()
                .is_some_and(|x| x.starts_with(p.as_str()))
        {
            return false;
        }
        let want = |actual: Option<String>, expected: &str| match actual {
            Some(a) => expected == "*" || a == expected,
            None => false,
        };
        if !self
            .headers
            .iter()
            .all(|(k, v)| want(header(env, k).map(str::to_owned), v))
        {
            return false;
        }
        if !self.claims.iter().all(|(k, v)| want(claim(env, k), v)) {
            return false;
        }
        if let Some(prefix) = &self.bearer_prefix
            && !bearer(env).is_some_and(|t| t.starts_with(prefix.as_str()))
        {
            return false;
        }
        if let Some(needle) = &self.body_contains
            && !decoded_body(env).is_some_and(|b| b.contains(needle.as_str()))
        {
            return false;
        }
        true
    }
}

impl Outcome {
    fn respond(&self, env: &Value) -> Response<Full<Bytes>> {
        let mut resp = self.respond_inner(env);
        if let Some(cc) = &self.cache_control
            && let Ok(v) = http::HeaderValue::from_str(cc)
        {
            resp.headers_mut().insert(http::header::CACHE_CONTROL, v);
        }
        resp
    }

    fn respond_inner(&self, env: &Value) -> Response<Full<Bytes>> {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        if status.is_success() {
            if self.inject.is_empty() {
                return text(StatusCode::NO_CONTENT, "");
            }
            let headers: BTreeMap<&str, String> = self
                .inject
                .iter()
                .map(|(k, v)| (k.as_str(), expand(v, env)))
                .collect();
            return json_response(status, &json!({ "headers": headers }));
        }
        let mut resp = Response::builder().status(status);
        if let Some(w) = &self.www_authenticate {
            resp = resp.header("www-authenticate", w);
        }
        let body = self.body.clone().unwrap_or_default();
        if body.trim_start().starts_with('{') {
            resp = resp.header("content-type", "application/json");
        }
        resp.body(Full::new(Bytes::from(body))).unwrap()
    }
}

/// Expand `{claims.X}`, `{header.X}`, `{bearer_suffix}`, `{method}`, `{path}`.
/// Unknown or missing placeholders expand to an empty string.
fn expand(template: &str, env: &Value) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let Some(close) = rest[open..].find('}') else {
            out.push_str(&rest[open..]);
            return out;
        };
        let key = &rest[open + 1..open + close];
        let value = if let Some(c) = key.strip_prefix("claims.") {
            claim(env, c)
        } else if let Some(h) = key.strip_prefix("header.") {
            header(env, h).map(str::to_owned)
        } else {
            match key {
                "bearer_suffix" => bearer(env)
                    .map(|t| t.split_once('-').map_or(t, |(_, suffix)| suffix).to_owned()),
                "method" | "path" => env[key].as_str().map(str::to_owned),
                _ => None,
            }
        };
        out.push_str(&value.unwrap_or_default());
        rest = &rest[open + close + 1..];
    }
    out.push_str(rest);
    out
}

fn header<'a>(env: &'a Value, name: &str) -> Option<&'a str> {
    env["headers"][name.to_ascii_lowercase()].as_str()
}

fn claim(env: &Value, name: &str) -> Option<String> {
    match &env["claims"][name] {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

fn bearer(env: &Value) -> Option<&str> {
    let v = header(env, "authorization")?;
    v.strip_prefix("Bearer ")
        .or_else(|| v.strip_prefix("bearer "))
}

fn decoded_body(env: &Value) -> Option<String> {
    use base64::Engine;
    let body = env["body"].as_str()?;
    if env["is_base64_encoded"].as_bool() == Some(true) {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(body)
            .ok()?;
        Some(String::from_utf8_lossy(&bytes).into_owned())
    } else {
        Some(body.to_owned())
    }
}

fn log(env: &Value, rule: &str, status: u16) {
    eprintln!(
        "{} {} {} -> {status} ({rule})",
        env["request_id"].as_str().unwrap_or("-"),
        env["method"].as_str().unwrap_or("-"),
        env["path"].as_str().unwrap_or("-"),
    );
}

fn text(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(body.to_owned())))
        .unwrap()
}

fn json_response(status: StatusCode, v: &Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(v.to_string())))
        .unwrap()
}
