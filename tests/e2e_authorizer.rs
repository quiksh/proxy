//! End-to-end tests for external HTTP authorizers (`[[authorizers]]`).

mod common;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use quik::config::{AuthorizerConfig, AuthorizerOnError, RouteConfig};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use common::{Backend, ProxySpec, https_client_http1_only};

fn url(proxy_addr: SocketAddr, path: &str) -> String {
    format!("https://localhost:{}{}", proxy_addr.port(), path)
}

/// Canned authorizer reply: status, headers, body.
type Reply = (u16, Vec<(&'static str, &'static str)>, String);

/// A mock authorizer. Records every envelope it receives and answers with
/// whatever `respond` returns for it.
struct MockAuthorizer {
    addr: SocketAddr,
    envelopes: Arc<Mutex<Vec<Value>>>,
}

impl MockAuthorizer {
    async fn spawn(respond: impl Fn(&Value) -> Reply + Send + Sync + 'static) -> Self {
        Self::spawn_with_delay(Duration::ZERO, respond).await
    }

    async fn spawn_with_delay(
        delay: Duration,
        respond: impl Fn(&Value) -> Reply + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let envelopes = Arc::new(Mutex::new(Vec::new()));
        let respond = Arc::new(respond);
        let recorded = envelopes.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let respond = respond.clone();
                let recorded = recorded.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let respond = respond.clone();
                        let recorded = recorded.clone();
                        async move {
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            let envelope: Value = serde_json::from_slice(&body).unwrap();
                            let (status, headers, body) = respond(&envelope);
                            recorded.lock().unwrap().push(envelope);
                            tokio::time::sleep(delay).await;
                            let mut resp = Response::builder().status(status);
                            for (k, v) in headers {
                                resp = resp.header(k, v);
                            }
                            Ok::<_, Infallible>(resp.body(Full::new(Bytes::from(body))).unwrap())
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tcp), svc)
                        .await;
                });
            }
        });
        Self { addr, envelopes }
    }

    fn envelopes(&self) -> Vec<Value> {
        self.envelopes.lock().unwrap().clone()
    }
}

fn authorizer_config(addr: SocketAddr) -> AuthorizerConfig {
    AuthorizerConfig {
        name: "internal".into(),
        url: format!("http://{addr}/authorize"),
        timeout_ms: 1000,
        forward_headers: vec!["authorization".into(), "x-api-key".into()],
        inject_headers: vec!["x-user-id".into(), "x-tenant-id".into()],
        on_error: AuthorizerOnError::Deny,
        include_body: false,
        max_body_bytes: 64 * 1024,
        body_timeout_ms: 10_000,
        tls: Default::default(),
    }
}

fn with_body(addr: SocketAddr, max_body_bytes: u64) -> AuthorizerConfig {
    AuthorizerConfig {
        include_body: true,
        max_body_bytes,
        ..authorizer_config(addr)
    }
}

async fn harness(authz: AuthorizerConfig) -> (Backend, common::ProxyHandle) {
    let backend = Backend::spawn("a").await;
    let proxy = common::spawn_proxy_with_authorizers(
        ProxySpec {
            pools: vec![common::Backends::http("p", vec![backend.addr])],
            routes: vec![RouteConfig {
                path_prefix: Some("/api".to_string()),
                authorizer: Some(authz.name.clone()),
                upstream: "p".to_string(),
                ..Default::default()
            }],
        },
        vec![],
        vec![authz],
    )
    .await;
    (backend, proxy)
}

fn allow_with(headers: Value) -> Reply {
    (
        200,
        vec![("content-type", "application/json")],
        json!({ "headers": headers }).to_string(),
    )
}

#[tokio::test]
async fn allow_injects_allowlisted_headers_and_sends_envelope() {
    let authz = MockAuthorizer::spawn(|_| {
        allow_with(json!({
            "x-user-id": "u_123",
            "X-Tenant-Id": "t_456",
            "x-not-allowed": "dropped",
        }))
    })
    .await;
    let (backend, proxy) = harness(authorizer_config(authz.addr)).await;

    let resp = https_client_http1_only()
        .post(url(proxy.addr, "/api/orders?limit=5"))
        .header("authorization", "Bearer abc")
        .header("cookie", "session=secret")
        .body("payload")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let calls = backend.calls();
    assert_eq!(calls.len(), 1);
    let h = &calls[0].headers;
    assert_eq!(h.get("x-user-id").unwrap(), "u_123");
    assert_eq!(h.get("x-tenant-id").unwrap(), "t_456");
    assert!(h.get("x-not-allowed").is_none());
    // The original request body is forwarded untouched.
    assert_eq!(&calls[0].body[..], b"payload");

    let envs = authz.envelopes();
    assert_eq!(envs.len(), 1);
    let env = &envs[0];
    assert_eq!(env["version"], "1");
    assert_eq!(env["method"], "POST");
    assert_eq!(env["path"], "/api/orders");
    assert_eq!(env["query"], "limit=5");
    assert_eq!(env["source_ip"], "127.0.0.1");
    assert_eq!(env["headers"]["authorization"], "Bearer abc");
    assert!(
        env["headers"].get("cookie").is_none(),
        "only forward_headers are sent"
    );
    assert!(env["request_id"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(
        env.get("body").is_none(),
        "body only sent with include_body"
    );
}

#[tokio::test]
async fn empty_2xx_is_a_plain_allow() {
    let authz = MockAuthorizer::spawn(|_| (204, vec![], String::new())).await;
    let (backend, proxy) = harness(authorizer_config(authz.addr)).await;

    let resp = https_client_http1_only()
        .get(url(proxy.addr, "/api/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(backend.calls().len(), 1);
}

#[tokio::test]
async fn deny_relays_status_body_and_challenge() {
    let authz = MockAuthorizer::spawn(|_| {
        (
            401,
            vec![
                ("content-type", "application/json"),
                ("www-authenticate", "Bearer realm=\"api\""),
                ("x-internal-debug", "leak"),
            ],
            r#"{"message":"token revoked"}"#.into(),
        )
    })
    .await;
    let (backend, proxy) = harness(authorizer_config(authz.addr)).await;

    let resp = https_client_http1_only()
        .get(url(proxy.addr, "/api/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers().get("www-authenticate").unwrap(),
        "Bearer realm=\"api\""
    );
    assert!(resp.headers().get("x-internal-debug").is_none());
    assert_eq!(resp.text().await.unwrap(), r#"{"message":"token revoked"}"#);
    assert!(backend.calls().is_empty(), "denied request reached backend");
}

#[tokio::test]
async fn authorizer_5xx_fails_closed_by_default() {
    let authz = MockAuthorizer::spawn(|_| (500, vec![], "boom".into())).await;
    let (backend, proxy) = harness(authorizer_config(authz.addr)).await;

    let resp = https_client_http1_only()
        .get(url(proxy.addr, "/api/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(backend.calls().is_empty());
}

#[tokio::test]
async fn malformed_allow_body_fails_closed() {
    let authz = MockAuthorizer::spawn(|_| (200, vec![], "not json".into())).await;
    let (backend, proxy) = harness(authorizer_config(authz.addr)).await;

    let resp = https_client_http1_only()
        .get(url(proxy.addr, "/api/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(backend.calls().is_empty());
}

#[tokio::test]
async fn timeout_fails_closed() {
    let authz =
        MockAuthorizer::spawn_with_delay(Duration::from_millis(500), |_| allow_with(json!({})))
            .await;
    let mut cfg = authorizer_config(authz.addr);
    cfg.timeout_ms = 50;
    let (backend, proxy) = harness(cfg).await;

    let resp = https_client_http1_only()
        .get(url(proxy.addr, "/api/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(backend.calls().is_empty());
}

#[tokio::test]
async fn on_error_allow_fails_open_without_injected_headers() {
    let authz = MockAuthorizer::spawn(|_| (503, vec![], String::new())).await;
    let mut cfg = authorizer_config(authz.addr);
    cfg.on_error = AuthorizerOnError::Allow;
    let (backend, proxy) = harness(cfg).await;

    let resp = https_client_http1_only()
        .get(url(proxy.addr, "/api/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let calls = backend.calls();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].headers.get("x-user-id").is_none());
}

/// SECURITY: a client must not be able to pre-set a header the authorizer is
/// allowed to inject - the request is rejected before the authorizer is called.
#[tokio::test]
async fn client_supplied_reserved_header_is_rejected() {
    let authz = MockAuthorizer::spawn(|_| allow_with(json!({}))).await;
    let (backend, proxy) = harness(authorizer_config(authz.addr)).await;

    let resp = https_client_http1_only()
        .get(url(proxy.addr, "/api/x"))
        .header("X-User-Id", "admin")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        authz.envelopes().is_empty(),
        "authorizer must not be called"
    );
    assert!(backend.calls().is_empty());
}

#[tokio::test]
async fn routes_without_authorizer_are_unaffected() {
    let authz = MockAuthorizer::spawn(|_| (403, vec![], String::new())).await;
    let backend = Backend::spawn("a").await;
    let proxy = common::spawn_proxy_with_authorizers(
        ProxySpec {
            pools: vec![common::Backends::http("p", vec![backend.addr])],
            routes: vec![
                RouteConfig {
                    path_prefix: Some("/api".to_string()),
                    authorizer: Some("internal".to_string()),
                    upstream: "p".to_string(),
                    ..Default::default()
                },
                common::route("/public", "p"),
            ],
        },
        vec![],
        vec![authorizer_config(authz.addr)],
    )
    .await;

    let client = https_client_http1_only();
    let denied = client.get(url(proxy.addr, "/api/x")).send().await.unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let open = client
        .get(url(proxy.addr, "/public/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(open.status(), StatusCode::OK);
    assert_eq!(authz.envelopes().len(), 1);
}

/// JWT runs first; the authorizer receives the verified claims.
#[tokio::test]
async fn jwt_claims_are_forwarded_to_authorizer() {
    let signer = common::TestJwtSigner::with_kid("k1");
    let (jwks_addr, _jwks) = common::spawn_jwks_server(signer.jwks_json());
    let authz = MockAuthorizer::spawn(|env| {
        if env["claims"]["sub"] == "user-42" {
            allow_with(json!({ "x-tenant-id": "t_1" }))
        } else {
            (403, vec![], String::new())
        }
    })
    .await;
    let backend = Backend::spawn("a").await;
    let proxy = common::spawn_proxy_with_authorizers(
        ProxySpec {
            pools: vec![common::Backends::http("p", vec![backend.addr])],
            routes: vec![RouteConfig {
                path_prefix: Some("/".to_string()),
                auth: Some("main".to_string()),
                authorizer: Some("internal".to_string()),
                upstream: "p".to_string(),
                ..Default::default()
            }],
        },
        vec![quik::config::AuthBlockConfig {
            name: "main".into(),
            jwks_url: format!("http://{jwks_addr}/jwks.json"),
            issuer: None,
            audience: None,
            algorithms: vec!["EdDSA".into()],
            required_claims: vec![],
            inject_headers: vec![],
        }],
        vec![authorizer_config(authz.addr)],
    )
    .await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = signer.sign(json!({ "sub": "user-42", "exp": now + 60 }));
    let client = https_client_http1_only();

    // No token → JWT rejects before the authorizer is consulted.
    let resp = client.get(url(proxy.addr, "/x")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(authz.envelopes().is_empty());

    let resp = client
        .get(url(proxy.addr, "/x"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        backend.calls()[0].headers.get("x-tenant-id").unwrap(),
        "t_1"
    );
}

/// SECURITY: WebSocket upgrades go through the authorizer like any request.
#[tokio::test]
async fn websocket_upgrade_consults_authorizer() {
    use tokio_tungstenite::Connector;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let authz = MockAuthorizer::spawn(|env| {
        if env["headers"]["x-api-key"] == "good" {
            allow_with(json!({ "x-user-id": "u_ws" }))
        } else {
            (403, vec![], String::new())
        }
    })
    .await;
    let backend = Backend::spawn_ws_echo("ws").await;
    let cfg = authorizer_config(authz.addr);
    let proxy = common::spawn_proxy_with_authorizers(
        ProxySpec {
            pools: vec![common::Backends::http("p", vec![backend.addr])],
            routes: vec![RouteConfig {
                path_prefix: Some("/".to_string()),
                authorizer: Some("internal".to_string()),
                upstream: "p".to_string(),
                ..Default::default()
            }],
        },
        vec![],
        vec![cfg],
    )
    .await;

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(common::TestNoVerifier))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls = Arc::new(tls);
    let ws_url = format!("wss://localhost:{}/echo", proxy.addr.port());

    let connect = |key: &'static str| {
        let mut req = ws_url.as_str().into_client_request().unwrap();
        req.headers_mut().insert("x-api-key", key.parse().unwrap());
        tokio_tungstenite::connect_async_tls_with_config(
            req,
            None,
            false,
            Some(Connector::Rustls(tls.clone())),
        )
    };

    match connect("bad").await {
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            assert_eq!(resp.status(), StatusCode::FORBIDDEN)
        }
        other => panic!("expected 403, got {:?}", other.map(|(_, r)| r.status())),
    }

    let (mut ws, resp) = connect("good").await.expect("authorised upgrade");
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
    ws.close(None).await.unwrap();
    assert_eq!(authz.envelopes().len(), 2);
}

// ── include_body ────────────────────────────────────────────────────────────

#[tokio::test]
async fn include_body_sends_utf8_body_and_forwards_same_bytes() {
    let authz = MockAuthorizer::spawn(|env| {
        let body: Value = serde_json::from_str(env["body"].as_str().unwrap()).unwrap();
        if body["amount"].as_u64().unwrap() <= 100 {
            allow_with(json!({ "x-user-id": "u_1" }))
        } else {
            (403, vec![], "over limit".into())
        }
    })
    .await;
    let (backend, proxy) = harness(with_body(authz.addr, 1024)).await;
    let client = https_client_http1_only();

    let resp = client
        .post(url(proxy.addr, "/api/pay"))
        .body(r#"{"amount":50}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let calls = backend.calls();
    assert_eq!(&calls[0].body[..], br#"{"amount":50}"#);
    assert_eq!(calls[0].headers.get("x-user-id").unwrap(), "u_1");
    assert_eq!(authz.envelopes()[0]["is_base64_encoded"], false);

    let resp = client
        .post(url(proxy.addr, "/api/pay"))
        .body(r#"{"amount":500}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.text().await.unwrap(), "over limit");
    assert_eq!(
        backend.calls().len(),
        1,
        "denied body must not reach backend"
    );
}

#[tokio::test]
async fn include_body_base64_encodes_binary() {
    let authz = MockAuthorizer::spawn(|_| (204, vec![], String::new())).await;
    let (backend, proxy) = harness(with_body(authz.addr, 1024)).await;

    let resp = https_client_http1_only()
        .post(url(proxy.addr, "/api/blob"))
        .body(vec![0xffu8, 0x00, 0x10])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let env = &authz.envelopes()[0];
    assert_eq!(env["body"], "/wAQ");
    assert_eq!(env["is_base64_encoded"], true);
    assert_eq!(&backend.calls()[0].body[..], &[0xff, 0x00, 0x10]);
}

#[tokio::test]
async fn include_body_empty_body_is_empty_string() {
    let authz = MockAuthorizer::spawn(|_| (204, vec![], String::new())).await;
    let (_backend, proxy) = harness(with_body(authz.addr, 1024)).await;

    let resp = https_client_http1_only()
        .get(url(proxy.addr, "/api/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(authz.envelopes()[0]["body"], "");
}

#[tokio::test]
async fn include_body_over_cap_by_content_length_is_413() {
    let authz = MockAuthorizer::spawn(|_| (204, vec![], String::new())).await;
    let (backend, proxy) = harness(with_body(authz.addr, 16)).await;

    let resp = https_client_http1_only()
        .post(url(proxy.addr, "/api/x"))
        .body("x".repeat(17))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(authz.envelopes().is_empty());
    assert!(backend.calls().is_empty());
}

#[tokio::test]
async fn include_body_over_cap_chunked_is_413() {
    let authz = MockAuthorizer::spawn(|_| (204, vec![], String::new())).await;
    let (backend, proxy) = harness(with_body(authz.addr, 16)).await;

    // A streamed body has no Content-Length, so the cap trips mid-read.
    let chunks: Vec<Result<&'static str, std::io::Error>> =
        vec![Ok("0123456789"), Ok("0123456789")];
    let resp = https_client_http1_only()
        .post(url(proxy.addr, "/api/x"))
        .body(reqwest::Body::wrap_stream(futures::stream::iter(chunks)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(authz.envelopes().is_empty());
    assert!(backend.calls().is_empty());
}

#[tokio::test]
async fn include_body_respects_lower_route_max_body_bytes() {
    let authz = MockAuthorizer::spawn(|_| (204, vec![], String::new())).await;
    let backend = Backend::spawn("a").await;
    let proxy = common::spawn_proxy_with_authorizers(
        ProxySpec {
            pools: vec![common::Backends::http("p", vec![backend.addr])],
            routes: vec![RouteConfig {
                path_prefix: Some("/api".to_string()),
                authorizer: Some("internal".to_string()),
                max_body_bytes: Some(8),
                upstream: "p".to_string(),
                ..Default::default()
            }],
        },
        vec![],
        vec![with_body(authz.addr, 1024)],
    )
    .await;

    let chunks: Vec<Result<&'static str, std::io::Error>> = vec![Ok("0123456789")];
    let resp = https_client_http1_only()
        .post(url(proxy.addr, "/api/x"))
        .body(reqwest::Body::wrap_stream(futures::stream::iter(chunks)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(authz.envelopes().is_empty());
}

/// A declared body over the route's `max_body_bytes` is refused before the
/// authorizer is called - no round trip for a request we'd reject anyway.
#[tokio::test]
async fn oversized_content_length_skips_authorizer() {
    let authz = MockAuthorizer::spawn(|_| (204, vec![], String::new())).await;
    let backend = Backend::spawn("a").await;
    let proxy = common::spawn_proxy_with_authorizers(
        ProxySpec {
            pools: vec![common::Backends::http("p", vec![backend.addr])],
            routes: vec![RouteConfig {
                path_prefix: Some("/api".to_string()),
                authorizer: Some("internal".to_string()),
                max_body_bytes: Some(8),
                upstream: "p".to_string(),
                ..Default::default()
            }],
        },
        vec![],
        vec![authorizer_config(authz.addr)],
    )
    .await;

    let resp = https_client_http1_only()
        .post(url(proxy.addr, "/api/x"))
        .body("x".repeat(64))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(authz.envelopes().is_empty());
}

/// A client that never finishes sending its body gets 408 instead of holding
/// a buffer open indefinitely.
#[tokio::test]
async fn include_body_slow_sender_times_out() {
    let authz = MockAuthorizer::spawn(|_| (204, vec![], String::new())).await;
    let mut cfg = with_body(authz.addr, 1024);
    cfg.body_timeout_ms = 100;
    let (backend, proxy) = harness(cfg).await;

    // First chunk arrives, then the stream stalls well past the deadline.
    let stream = futures::stream::unfold(0u8, |n| async move {
        match n {
            0 => Some((Ok::<_, std::io::Error>("partial"), 1)),
            _ => {
                tokio::time::sleep(Duration::from_secs(5)).await;
                None
            }
        }
    });
    let resp = https_client_http1_only()
        .post(url(proxy.addr, "/api/x"))
        .body(reqwest::Body::wrap_stream(stream))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
    assert!(authz.envelopes().is_empty());
    assert!(backend.calls().is_empty());
}
