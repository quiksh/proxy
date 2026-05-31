//! End-to-end proxy tests over real TLS, real HTTP/1+2, real backends.
//!
//! All e2e tests live in this single integration binary because the prometheus
//! global recorder can only be installed once per process.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use quik::config::RouteConfig;
use serde_json::Value;

use common::{Backend, ProxySpec, https_client, https_client_http1_only, route, spawn_proxy};

fn url(proxy_addr: SocketAddr, path: &str) -> String {
    format!("https://localhost:{}{}", proxy_addr.port(), path)
}

async fn one_pool_one_route(prefix: &str) -> (Backend, common::ProxyHandle) {
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("pool-a", vec![backend.addr])],
        routes: vec![route(prefix, "pool-a")],
    })
    .await;
    (backend, proxy)
}

#[tokio::test]
async fn http2_via_alpn_happy_path() {
    let (backend, proxy) = one_pool_one_route("/api").await;
    let client = https_client();

    let resp = client
        .get(url(proxy.addr, "/api/hello"))
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.version(), reqwest::Version::HTTP_2);
    assert_eq!(
        resp.headers()
            .get("x-backend-name")
            .and_then(|v| v.to_str().ok()),
        Some("a")
    );

    let json: Value = resp.json().await.expect("json");
    assert_eq!(json["echoed_path"], "/api/hello");

    let calls = backend.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].path, "/api/hello");
}

#[tokio::test]
async fn http1_happy_path() {
    let (backend, proxy) = one_pool_one_route("/api").await;
    let client = https_client_http1_only();

    let resp = client
        .get(url(proxy.addr, "/api/v1/widgets/42"))
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.version(), reqwest::Version::HTTP_11);

    let calls = backend.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].path, "/api/v1/widgets/42");
}

#[tokio::test]
async fn request_body_streams_through_post() {
    let (backend, proxy) = one_pool_one_route("/api").await;
    let client = https_client();

    let payload = "x".repeat(64 * 1024);
    let resp = client
        .post(url(proxy.addr, "/api/upload"))
        .body(payload.clone())
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), StatusCode::OK);
    let calls = backend.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].method, http::Method::POST);
    assert_eq!(calls[0].body, Bytes::from(payload));
}

#[tokio::test]
async fn hop_by_hop_headers_are_stripped() {
    let (backend, proxy) = one_pool_one_route("/api").await;
    let client = https_client_http1_only();

    let resp = client
        .get(url(proxy.addr, "/api/x"))
        .header("x-tenant", "acme")
        .header("connection", "close, x-secret")
        .header("x-secret", "do-not-forward")
        .header("transfer-encoding", "chunked")
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), StatusCode::OK);
    let calls = backend.calls();
    assert_eq!(calls.len(), 1);
    let h = &calls[0].headers;
    assert!(
        h.get("connection").is_none(),
        "connection should be stripped"
    );
    assert!(
        h.get("transfer-encoding").is_none(),
        "transfer-encoding should be stripped"
    );
    assert!(
        h.get("x-secret").is_none(),
        "header listed in Connection should be stripped"
    );
    assert_eq!(
        h.get("x-tenant").and_then(|v| v.to_str().ok()),
        Some("acme")
    );
}

#[tokio::test]
async fn unknown_route_returns_404() {
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("pool-a", vec![backend.addr])],
        routes: vec![route("/api", "pool-a")],
    })
    .await;
    let client = https_client();

    let resp = client
        .get(url(proxy.addr, "/no/such/route"))
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(backend.calls().len(), 0);
}

#[tokio::test]
async fn dead_upstream_returns_502() {
    let unused: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("pool-dead", vec![unused])],
        routes: vec![route("/", "pool-dead")],
    })
    .await;
    let client = https_client();

    let resp = client
        .get(url(proxy.addr, "/anything"))
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn round_robin_distributes_across_members() {
    let backend_a = Backend::spawn("a").await;
    let backend_b = Backend::spawn("b").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http(
            "pool-ab",
            vec![backend_a.addr, backend_b.addr],
        )],
        routes: vec![route("/", "pool-ab")],
    })
    .await;
    let client = https_client_http1_only();

    let mut seen_a = 0;
    let mut seen_b = 0;
    for _ in 0..10 {
        let resp = client
            .get(url(proxy.addr, "/x"))
            .send()
            .await
            .expect("send");
        match resp
            .headers()
            .get("x-backend-name")
            .and_then(|v| v.to_str().ok())
        {
            Some("a") => seen_a += 1,
            Some("b") => seen_b += 1,
            other => panic!("unexpected backend: {other:?}"),
        }
    }
    assert!(seen_a > 0, "backend a never selected");
    assert!(seen_b > 0, "backend b never selected");
    assert_eq!(seen_a + seen_b, 10);
}

#[tokio::test]
async fn admin_healthz_returns_ok_then_503_on_drain() {
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("p", vec![backend.addr])],
        routes: vec![route("/", "p")],
    })
    .await;
    let admin_url = format!("http://{}/healthz", proxy.admin_addr);

    let client = reqwest::Client::new();
    let resp = client.get(&admin_url).send().await.expect("admin");
    assert_eq!(resp.status(), StatusCode::OK);

    proxy.shutdown.trigger_drain();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let resp = client.get(&admin_url).send().await.expect("admin");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

// ── per-route modules (timeout / strip_prefix / max_body_bytes) ─────────────

#[tokio::test]
async fn wildcard_subdomain_host_routes_correctly() {
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("p", vec![backend.addr])],
        routes: vec![RouteConfig {
            hosts: vec!["*.example.com".to_string()],
            path_prefix: Some("/".to_string()),
            upstream: "p".to_string(),
            ..Default::default()
        }],
    })
    .await;
    let client = https_client();

    // Cert is for "localhost" but reqwest's danger_accept_invalid_certs lets us
    // override the Host header. We set Host manually so the proxy's route
    // matcher sees a subdomain of example.com.
    let resp = client
        .get(url(proxy.addr, "/x"))
        .header("host", "api.example.com")
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::OK);

    // A request whose Host doesn't end in .example.com should not match.
    let resp = client
        .get(url(proxy.addr, "/x"))
        .header("host", "other.org")
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn path_exact_beats_prefix() {
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("p", vec![backend.addr])],
        routes: vec![
            RouteConfig {
                path_exact: Some("/api/healthz".to_string()),
                upstream: "p".to_string(),
                ..Default::default()
            },
            RouteConfig {
                path_prefix: Some("/api".to_string()),
                upstream: "p".to_string(),
                ..Default::default()
            },
        ],
    })
    .await;
    let client = https_client();

    // Exact endpoint
    let resp = client
        .get(url(proxy.addr, "/api/healthz"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::OK);

    // Anything other than the exact path also gets 200 — but via the prefix route
    let resp = client
        .get(url(proxy.addr, "/api/x"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::OK);

    // /api/healthz/extra is NOT the exact match — falls through to prefix
    let resp = client
        .get(url(proxy.addr, "/api/healthz/extra"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::OK);

    // All three should have hit the backend
    assert_eq!(backend.calls().len(), 3);
}

#[tokio::test]
async fn strip_prefix_rewrites_forwarded_path() {
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("p", vec![backend.addr])],
        routes: vec![RouteConfig {
            path_prefix: Some("/api/v1".to_string()),
            strip_prefix: Some("/api/v1".to_string()),
            upstream: "p".to_string(),
            ..Default::default()
        }],
    })
    .await;
    let client = https_client();

    let resp = client
        .get(url(proxy.addr, "/api/v1/users/42?fields=name"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::OK);

    let calls = backend.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].path, "/users/42");
}

#[tokio::test]
async fn strip_prefix_to_root_when_path_equals_prefix() {
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("p", vec![backend.addr])],
        routes: vec![RouteConfig {
            path_exact: Some("/api/v1".to_string()),
            strip_prefix: Some("/api/v1".to_string()),
            upstream: "p".to_string(),
            ..Default::default()
        }],
    })
    .await;
    let client = https_client();

    let resp = client
        .get(url(proxy.addr, "/api/v1"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::OK);

    let calls = backend.calls();
    assert_eq!(calls[0].path, "/");
}

#[tokio::test]
async fn multi_method_route() {
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("p", vec![backend.addr])],
        routes: vec![RouteConfig {
            methods: vec!["GET".to_string(), "HEAD".to_string()],
            path_prefix: Some("/data".to_string()),
            upstream: "p".to_string(),
            ..Default::default()
        }],
    })
    .await;
    let client = https_client();

    assert_eq!(
        client
            .get(url(proxy.addr, "/data/x"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        client
            .head(url(proxy.addr, "/data/x"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    // PUT not in list → 404
    assert_eq!(
        client
            .put(url(proxy.addr, "/data/x"))
            .body("")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn upstream_timeout_returns_504() {
    let slow_backend = Backend::spawn_with_delay("slow", Duration::from_millis(300)).await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("p", vec![slow_backend.addr])],
        routes: vec![RouteConfig {
            path_prefix: Some("/".to_string()),
            timeout_ms: Some(50),
            upstream: "p".to_string(),
            ..Default::default()
        }],
    })
    .await;
    let client = https_client();

    let resp = client
        .get(url(proxy.addr, "/anything"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
}

// ── per-upstream byte counters + inflight gauge ─────────────────────────────

#[tokio::test]
async fn upstream_byte_counters_increment() {
    // Unique pool name so the counter lines for this test don't collide
    // with the shared metric recorder across parallel tests.
    let pool_name = format!("bytest-{}", quik::headers::random_request_id());
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http(&pool_name, vec![backend.addr])],
        routes: vec![RouteConfig {
            path_prefix: Some("/".to_string()),
            upstream: pool_name.clone(),
            ..Default::default()
        }],
    })
    .await;
    let client = https_client_http1_only();

    let req_body = "x".repeat(1024);
    let resp = client
        .post(url(proxy.addr, "/upload"))
        .body(req_body.clone())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::OK);
    let resp_body_bytes = resp.bytes().await.unwrap();

    // Scrape /metrics and assert the per-member counters reflect this exchange.
    let metrics_text = reqwest::Client::new()
        .get(format!("http://{}/metrics", proxy.admin_addr))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    fn parse_counter(text: &str, metric: &str, pool: &str) -> u64 {
        for line in text.lines() {
            if line.starts_with(metric)
                && line.contains(&format!("pool=\"{pool}\""))
                && !line.starts_with('#')
                && let Some(v) = line.split_whitespace().last()
                && let Ok(n) = v.parse::<u64>()
            {
                return n;
            }
        }
        0
    }

    let sent = parse_counter(&metrics_text, "quik_upstream_bytes_sent_total", &pool_name);
    let received = parse_counter(
        &metrics_text,
        "quik_upstream_bytes_received_total",
        &pool_name,
    );

    assert!(
        sent >= 1024,
        "bytes_sent_total should reflect the 1024-byte request body, got {sent}"
    );
    assert!(
        received >= resp_body_bytes.len() as u64,
        "bytes_received_total should reflect the response body ({} bytes), got {}",
        resp_body_bytes.len(),
        received
    );
}

// ── passive health + LeastConnections balancer ──────────────────────────────

fn tight_health() -> quik::config::UpstreamHealthConfig {
    // Short threshold + short windows so tests don't have to wait.
    quik::config::UpstreamHealthConfig {
        ejection_threshold: 3,
        ejection_base_ms: 150,
        ejection_max_ms: 1_000,
    }
}

#[tokio::test]
async fn passive_health_ejects_failing_member_and_routes_around_it() {
    use std::sync::atomic::Ordering;

    let (failing, status) = Backend::spawn_with_dynamic_status("failing").await;
    let healthy = Backend::spawn("healthy").await;
    status.store(503, Ordering::Relaxed);

    let proxy = spawn_proxy(ProxySpec {
        pools: vec![
            common::Backends::http("p", vec![failing.addr, healthy.addr])
                .with_health(tight_health()),
        ],
        routes: vec![route("/", "p")],
    })
    .await;
    let client = https_client_http1_only();

    // 20 sequential requests. With round-robin + threshold 3, the failing
    // member is picked at indices 0, 2, 4 → 3 failures → ejected. From then
    // on every request goes to the healthy member.
    for _ in 0..20 {
        let _ = client.get(url(proxy.addr, "/x")).send().await;
    }

    let failing_count = failing.calls().len();
    let healthy_count = healthy.calls().len();

    assert_eq!(
        failing_count, 3,
        "failing member should have received exactly threshold (3) requests before ejection, got {failing_count}"
    );
    assert_eq!(failing_count + healthy_count, 20);
    assert!(healthy_count >= 17, "healthy got {healthy_count}");
}

#[tokio::test]
async fn passive_health_recovers_after_backoff_window() {
    use std::sync::atomic::Ordering;

    let (member, status) = Backend::spawn_with_dynamic_status("flaky").await;
    status.store(503, Ordering::Relaxed);

    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("p", vec![member.addr]).with_health(tight_health())],
        routes: vec![route("/", "p")],
    })
    .await;
    let client = https_client_http1_only();

    // 3 failures → ejected. Backend is the only member, so the 4th request
    // can't be routed anywhere — proxy returns 503 itself.
    for _ in 0..3 {
        let r = client
            .get(url(proxy.addr, "/x"))
            .send()
            .await
            .expect("send");
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE); // backend's
    }
    let r = client
        .get(url(proxy.addr, "/x"))
        .send()
        .await
        .expect("send");
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = r.text().await.unwrap();
    assert!(
        body.contains("no upstream available"),
        "expected proxy-synthesised 503 body, got: {body:?}"
    );
    assert_eq!(
        member.calls().len(),
        3,
        "backend must not have been hit again after ejection"
    );

    // Flip backend to healthy and wait past the ejection window.
    status.store(200, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(250)).await;

    // The next request should be admitted as a probe, succeed, and clear
    // the ejection state.
    let r = client
        .get(url(proxy.addr, "/x"))
        .send()
        .await
        .expect("send");
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(member.calls().len(), 4);

    // And subsequent requests continue to work.
    for _ in 0..3 {
        let r = client
            .get(url(proxy.addr, "/x"))
            .send()
            .await
            .expect("send");
        assert_eq!(r.status(), StatusCode::OK);
    }
    assert_eq!(member.calls().len(), 7);
}

#[tokio::test]
async fn least_connections_routes_around_a_slow_member() {
    use quik::config::BalancerKind;

    let slow = Backend::spawn_with_delay("slow", Duration::from_millis(120)).await;
    let fast = Backend::spawn("fast").await;

    let proxy = spawn_proxy(ProxySpec {
        pools: vec![
            common::Backends::http("p", vec![slow.addr, fast.addr])
                .with_balancer(BalancerKind::LeastConnections),
        ],
        routes: vec![route("/", "p")],
    })
    .await;
    let client = https_client();
    let url_str = url(proxy.addr, "/x");

    // Stream requests in with a small gap rather than firing all at once.
    // Bursts of N pick all at once and decide based on a momentary snapshot —
    // LC's whole point is that it reacts to *completions* between picks, so
    // fast's inflight should drop back to 0 between launches while slow's
    // 120ms requests accumulate.
    let mut handles = Vec::with_capacity(30);
    for _ in 0..30 {
        let client = client.clone();
        let url = url_str.clone();
        handles.push(tokio::spawn(async move {
            let _ = client.get(&url).send().await;
        }));
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    for h in handles {
        let _ = h.await;
    }

    let slow_count = slow.calls().len();
    let fast_count = fast.calls().len();
    assert_eq!(slow_count + fast_count, 30);
    assert!(
        fast_count > slow_count * 2,
        "expected LC to favour fast member: fast={fast_count} slow={slow_count}"
    );
}

// ── inject_headers (JWT claims → upstream request headers) ──────────────────

fn auth_block_with_injects(
    name: &str,
    jwks_addr: SocketAddr,
    inject: Vec<quik::config::ClaimHeaderMapping>,
) -> quik::config::AuthBlockConfig {
    let mut a = auth_block(name, jwks_addr);
    a.inject_headers = inject;
    a
}

fn mapping(claim: &str, header: &str, required: bool) -> quik::config::ClaimHeaderMapping {
    quik::config::ClaimHeaderMapping {
        claim: claim.to_string(),
        header: header.to_string(),
        required,
    }
}

#[tokio::test]
async fn inject_headers_copies_string_claim_to_header() {
    let signer = common::TestJwtSigner::with_kid("k1");
    let (jwks_addr, _) = common::spawn_jwks_server(signer.jwks_json());
    let backend = common::Backend::spawn("a").await;
    let proxy = common::spawn_proxy_with_auth(
        ProxySpec {
            pools: vec![common::Backends::http("p", vec![backend.addr])],
            routes: vec![RouteConfig {
                path_prefix: Some("/".to_string()),
                auth: Some("main".to_string()),
                upstream: "p".to_string(),
                ..Default::default()
            }],
        },
        vec![auth_block_with_injects(
            "main",
            jwks_addr,
            vec![mapping("sub", "x-auth-sub", false)],
        )],
    )
    .await;

    let token = signer.sign(valid_claims());
    let client = https_client_http1_only();
    let resp = client
        .get(url(proxy.addr, "/x"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        backend.calls()[0].headers.get("x-auth-sub").unwrap(),
        "user-42"
    );
}

#[tokio::test]
async fn inject_headers_reject_spoofed_value_403() {
    let signer = common::TestJwtSigner::with_kid("k1");
    let (jwks_addr, _) = common::spawn_jwks_server(signer.jwks_json());
    let backend = common::Backend::spawn("a").await;
    let proxy = common::spawn_proxy_with_auth(
        ProxySpec {
            pools: vec![common::Backends::http("p", vec![backend.addr])],
            routes: vec![RouteConfig {
                path_prefix: Some("/".to_string()),
                auth: Some("main".to_string()),
                upstream: "p".to_string(),
                ..Default::default()
            }],
        },
        vec![auth_block_with_injects(
            "main",
            jwks_addr,
            vec![mapping("sub", "x-auth-sub", false)],
        )],
    )
    .await;

    let token = signer.sign(valid_claims());
    let client = https_client_http1_only();
    let resp = client
        .get(url(proxy.addr, "/x"))
        // any attempt to set a mapped header is rejected, not silently overwritten
        .header("x-auth-sub", "attacker-controlled")
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        backend.calls().len(),
        0,
        "request must not have reached the backend"
    );
}

#[tokio::test]
async fn inject_headers_reject_spoof_even_when_claim_missing() {
    // Mapped header is x-tenant-id but the JWT doesn't carry tenant_id and
    // the mapping is optional — under silent-overwrite semantics this would
    // pass through to the backend. With the loud-reject policy, the mere
    // presence of the reserved header on the inbound request is enough to
    // 403, regardless of whether we'd have injected anything.
    let signer = common::TestJwtSigner::with_kid("k1");
    let (jwks_addr, _) = common::spawn_jwks_server(signer.jwks_json());
    let backend = common::Backend::spawn("a").await;
    let proxy = common::spawn_proxy_with_auth(
        ProxySpec {
            pools: vec![common::Backends::http("p", vec![backend.addr])],
            routes: vec![RouteConfig {
                path_prefix: Some("/".to_string()),
                auth: Some("main".to_string()),
                upstream: "p".to_string(),
                ..Default::default()
            }],
        },
        vec![auth_block_with_injects(
            "main",
            jwks_addr,
            vec![mapping("tenant_id", "x-tenant-id", false)],
        )],
    )
    .await;

    let token = signer.sign(valid_claims());
    let client = https_client_http1_only();
    let resp = client
        .get(url(proxy.addr, "/x"))
        .header("x-tenant-id", "acme-attempting-to-spoof")
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(backend.calls().len(), 0);
}

#[tokio::test]
async fn inject_headers_handles_array_and_number_claims() {
    let signer = common::TestJwtSigner::with_kid("k1");
    let (jwks_addr, _) = common::spawn_jwks_server(signer.jwks_json());
    let backend = common::Backend::spawn("a").await;
    let proxy = common::spawn_proxy_with_auth(
        ProxySpec {
            pools: vec![common::Backends::http("p", vec![backend.addr])],
            routes: vec![RouteConfig {
                path_prefix: Some("/".to_string()),
                auth: Some("main".to_string()),
                upstream: "p".to_string(),
                ..Default::default()
            }],
        },
        vec![auth_block_with_injects(
            "main",
            jwks_addr,
            vec![
                mapping("roles", "x-roles", false),
                mapping("level", "x-level", false),
            ],
        )],
    )
    .await;

    let mut claims = valid_claims();
    claims["roles"] = serde_json::json!(["admin", "billing"]);
    claims["level"] = serde_json::json!(42);
    let token = signer.sign(claims);

    let client = https_client_http1_only();
    let _ = client
        .get(url(proxy.addr, "/x"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("send");

    let h = &backend.calls()[0].headers;
    assert_eq!(h.get("x-roles").unwrap(), "admin,billing");
    assert_eq!(h.get("x-level").unwrap(), "42");
}

#[tokio::test]
async fn inject_headers_required_missing_returns_403() {
    let signer = common::TestJwtSigner::with_kid("k1");
    let (jwks_addr, _) = common::spawn_jwks_server(signer.jwks_json());
    let backend = common::Backend::spawn("a").await;
    let proxy = common::spawn_proxy_with_auth(
        ProxySpec {
            pools: vec![common::Backends::http("p", vec![backend.addr])],
            routes: vec![RouteConfig {
                path_prefix: Some("/".to_string()),
                auth: Some("main".to_string()),
                upstream: "p".to_string(),
                ..Default::default()
            }],
        },
        vec![auth_block_with_injects(
            "main",
            jwks_addr,
            // tenant_id is required for header injection but the token
            // we sign below won't carry it
            vec![mapping("tenant_id", "x-tenant-id", true)],
        )],
    )
    .await;

    let token = signer.sign(valid_claims());
    let client = https_client_http1_only();
    let resp = client
        .get(url(proxy.addr, "/x"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(backend.calls().len(), 0);
}

#[tokio::test]
async fn inject_headers_optional_missing_is_silently_skipped() {
    let signer = common::TestJwtSigner::with_kid("k1");
    let (jwks_addr, _) = common::spawn_jwks_server(signer.jwks_json());
    let backend = common::Backend::spawn("a").await;
    let proxy = common::spawn_proxy_with_auth(
        ProxySpec {
            pools: vec![common::Backends::http("p", vec![backend.addr])],
            routes: vec![RouteConfig {
                path_prefix: Some("/".to_string()),
                auth: Some("main".to_string()),
                upstream: "p".to_string(),
                ..Default::default()
            }],
        },
        vec![auth_block_with_injects(
            "main",
            jwks_addr,
            vec![mapping("tenant_id", "x-tenant-id", false)], // optional
        )],
    )
    .await;

    let token = signer.sign(valid_claims());
    let client = https_client_http1_only();
    let resp = client
        .get(url(proxy.addr, "/x"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::OK);
    // Header should NOT be present since the claim is missing.
    assert!(backend.calls()[0].headers.get("x-tenant-id").is_none());
}

// ── JWT auth ────────────────────────────────────────────────────────────────

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn auth_block(name: &str, jwks_addr: SocketAddr) -> quik::config::AuthBlockConfig {
    quik::config::AuthBlockConfig {
        name: name.to_string(),
        jwks_url: format!("http://{jwks_addr}/jwks.json"),
        issuer: Some("https://issuer.test/".to_string()),
        audience: Some("api".to_string()),
        algorithms: vec!["EdDSA".to_string()],
        required_claims: vec!["sub".to_string()],
        inject_headers: vec![],
    }
}

fn valid_claims() -> serde_json::Value {
    serde_json::json!({
        "iss": "https://issuer.test/",
        "aud": "api",
        "sub": "user-42",
        "exp": unix_now() + 60,
        "iat": unix_now(),
    })
}

async fn auth_test_harness() -> (
    common::Backend,
    common::TestJwtSigner,
    quik::config::AuthBlockConfig,
    common::ProxyHandle,
) {
    let signer = common::TestJwtSigner::with_kid("k1");
    let (jwks_addr, _jwks_body) = common::spawn_jwks_server(signer.jwks_json());
    let backend = common::Backend::spawn("a").await;
    let auth = auth_block("main", jwks_addr);
    let proxy = common::spawn_proxy_with_auth(
        ProxySpec {
            pools: vec![common::Backends::http("p", vec![backend.addr])],
            routes: vec![RouteConfig {
                path_prefix: Some("/".to_string()),
                auth: Some("main".to_string()),
                upstream: "p".to_string(),
                ..Default::default()
            }],
        },
        vec![auth.clone()],
    )
    .await;
    (backend, signer, auth, proxy)
}

#[tokio::test]
async fn jwt_happy_path_valid_token_reaches_backend() {
    let (backend, signer, _auth, proxy) = auth_test_harness().await;
    let token = signer.sign(valid_claims());
    let client = https_client_http1_only();

    let resp = client
        .get(url(proxy.addr, "/x"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(backend.calls().len(), 1);
}

#[tokio::test]
async fn jwt_missing_token_returns_401() {
    let (backend, _signer, _auth, proxy) = auth_test_harness().await;
    let client = https_client_http1_only();

    let resp = client
        .get(url(proxy.addr, "/x"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(resp.headers().get("www-authenticate").unwrap(), "Bearer");
    assert_eq!(backend.calls().len(), 0);
}

#[tokio::test]
async fn jwt_bad_signature_returns_401() {
    let (backend, _legit_signer, _auth, proxy) = auth_test_harness().await;

    // Sign with a *different* keypair but advertise the matching kid — the
    // server will look up the (legit) key and the signature won't verify.
    let attacker = common::TestJwtSigner::with_kid("k1");
    let token = attacker.sign(valid_claims());

    let client = https_client_http1_only();
    let resp = client
        .get(url(proxy.addr, "/x"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(backend.calls().len(), 0);
}

#[tokio::test]
async fn jwt_wrong_issuer_returns_403() {
    let (backend, signer, _auth, proxy) = auth_test_harness().await;
    let mut claims = valid_claims();
    claims["iss"] = serde_json::Value::String("https://other.test/".into());
    let token = signer.sign(claims);

    let client = https_client_http1_only();
    let resp = client
        .get(url(proxy.addr, "/x"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    // claim-validation failures map to 403 (vs 401 for "no/bad token")
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(backend.calls().len(), 0);
}

#[tokio::test]
async fn jwt_wrong_audience_returns_403() {
    let (backend, signer, _auth, proxy) = auth_test_harness().await;
    let mut claims = valid_claims();
    claims["aud"] = serde_json::Value::String("wrong-api".into());
    let token = signer.sign(claims);

    let client = https_client_http1_only();
    let resp = client
        .get(url(proxy.addr, "/x"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(backend.calls().len(), 0);
}

#[tokio::test]
async fn jwt_expired_token_returns_403() {
    let (backend, signer, _auth, proxy) = auth_test_harness().await;
    let mut claims = valid_claims();
    // 1 hour in the past — well outside any reasonable clock-skew leeway.
    claims["exp"] = serde_json::Value::Number((unix_now() - 3600).into());
    let token = signer.sign(claims);

    let client = https_client_http1_only();
    let resp = client
        .get(url(proxy.addr, "/x"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(backend.calls().len(), 0);
}

#[tokio::test]
async fn jwt_missing_required_claim_returns_403() {
    let (backend, signer, _auth, proxy) = auth_test_harness().await;
    let mut claims = valid_claims();
    claims.as_object_mut().unwrap().remove("sub"); // sub is in required_claims
    let token = signer.sign(claims);

    let client = https_client_http1_only();
    let resp = client
        .get(url(proxy.addr, "/x"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(backend.calls().len(), 0);
}

#[tokio::test]
async fn jwt_kid_rotation_triggers_jwks_refresh() {
    // The JWKS endpoint starts with only an old key. A request signed by a
    // freshly-rotated key (different kid) misses the cache and triggers a
    // refresh — which we simulate by mutating the JWKS body between the
    // initial cache-fill and the second request.
    let old_signer = common::TestJwtSigner::with_kid("old");
    let new_signer = common::TestJwtSigner::with_kid("new");

    let (jwks_addr, jwks_body) = common::spawn_jwks_server(old_signer.jwks_json());
    let backend = common::Backend::spawn("a").await;
    let proxy = common::spawn_proxy_with_auth(
        ProxySpec {
            pools: vec![common::Backends::http("p", vec![backend.addr])],
            routes: vec![RouteConfig {
                path_prefix: Some("/".to_string()),
                auth: Some("main".to_string()),
                upstream: "p".to_string(),
                ..Default::default()
            }],
        },
        vec![auth_block("main", jwks_addr)],
    )
    .await;
    let client = https_client_http1_only();

    // Rotate: serve the new key from the JWKS endpoint.
    *jwks_body.lock().unwrap() = new_signer.jwks_json();

    // First request signed with the rotated (new) key. We expect a JWKS
    // refresh on kid miss, then successful validation.
    let token = new_signer.sign(valid_claims());
    let resp = client
        .get(url(proxy.addr, "/x"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::OK, "JWKS should have refreshed");
    assert_eq!(backend.calls().len(), 1);
}

// ── identity / forwarding headers ───────────────────────────────────────────

#[tokio::test]
async fn xff_edge_mode_replaces_spoofed_value() {
    use quik::config::Mode;
    let backend = Backend::spawn("a").await;
    let proxy = common::spawn_proxy_with_mode(
        ProxySpec {
            pools: vec![common::Backends::http("p", vec![backend.addr])],
            routes: vec![route("/", "p")],
        },
        Mode::Edge,
    )
    .await;
    let client = https_client_http1_only();

    let resp = client
        .get(url(proxy.addr, "/x"))
        .header("x-forwarded-for", "203.0.113.99") // attacker-supplied
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::OK);

    let calls = backend.calls();
    let xff = calls[0]
        .headers
        .get("x-forwarded-for")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(
        xff, "127.0.0.1",
        "edge mode should replace inbound XFF with peer IP, got {xff}"
    );
}

#[tokio::test]
async fn xff_host_mode_appends_to_existing_chain() {
    use quik::config::Mode;
    let backend = Backend::spawn("a").await;
    let proxy = common::spawn_proxy_with_mode(
        ProxySpec {
            pools: vec![common::Backends::http("p", vec![backend.addr])],
            routes: vec![route("/", "p")],
        },
        Mode::Host,
    )
    .await;
    let client = https_client_http1_only();

    let resp = client
        .get(url(proxy.addr, "/x"))
        .header("x-forwarded-for", "203.0.113.5, 10.0.0.1") // existing chain
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::OK);

    let xff = backend.calls()[0]
        .headers
        .get("x-forwarded-for")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        xff, "203.0.113.5, 10.0.0.1, 127.0.0.1",
        "host mode should append peer to existing chain"
    );
}

#[tokio::test]
async fn x_forwarded_proto_and_host_are_set() {
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("p", vec![backend.addr])],
        routes: vec![route("/", "p")],
    })
    .await;
    let client = https_client_http1_only();

    let _ = client
        .get(url(proxy.addr, "/x"))
        .header("host", "api.example.com")
        .send()
        .await
        .expect("send");

    let h = &backend.calls()[0].headers;
    assert_eq!(h.get("x-forwarded-proto").unwrap(), "https");
    assert_eq!(h.get("x-forwarded-host").unwrap(), "api.example.com");
}

#[tokio::test]
async fn request_id_passthrough_when_supplied() {
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("p", vec![backend.addr])],
        routes: vec![route("/", "p")],
    })
    .await;
    let client = https_client_http1_only();

    let _ = client
        .get(url(proxy.addr, "/x"))
        .header("x-request-id", "client-supplied-trace-id")
        .send()
        .await
        .expect("send");

    assert_eq!(
        backend.calls()[0].headers.get("x-request-id").unwrap(),
        "client-supplied-trace-id"
    );
}

#[tokio::test]
async fn request_id_generated_when_absent() {
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("p", vec![backend.addr])],
        routes: vec![route("/", "p")],
    })
    .await;
    let client = https_client_http1_only();
    let _ = client
        .get(url(proxy.addr, "/x"))
        .send()
        .await
        .expect("send");

    let calls = backend.calls();
    let got = calls[0]
        .headers
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(got.len(), 36, "should be UUIDv4-shaped: {got}");
    assert_eq!(got.chars().nth(14).unwrap(), '4', "version 4 nibble");
}

#[tokio::test]
async fn traceparent_passthrough_when_valid() {
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("p", vec![backend.addr])],
        routes: vec![route("/", "p")],
    })
    .await;
    let client = https_client_http1_only();

    let supplied = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    let _ = client
        .get(url(proxy.addr, "/x"))
        .header("traceparent", supplied)
        .send()
        .await
        .expect("send");

    assert_eq!(
        backend.calls()[0].headers.get("traceparent").unwrap(),
        supplied
    );
}

#[tokio::test]
async fn traceparent_generated_when_invalid_or_missing() {
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("p", vec![backend.addr])],
        routes: vec![route("/", "p")],
    })
    .await;
    let client = https_client_http1_only();

    // missing
    let _ = client
        .get(url(proxy.addr, "/a"))
        .send()
        .await
        .expect("send");
    // malformed
    let _ = client
        .get(url(proxy.addr, "/b"))
        .header("traceparent", "not-a-valid-traceparent")
        .send()
        .await
        .expect("send");

    let calls = backend.calls();
    for c in &calls {
        let tp = c.headers.get("traceparent").unwrap().to_str().unwrap();
        assert!(
            quik::headers::valid_traceparent(tp),
            "generated traceparent should validate: {tp}"
        );
    }
}

// ── HTTPS upstream + h2 upstream ────────────────────────────────────────────

#[tokio::test]
async fn https_upstream_h1_inbound() {
    let backend = Backend::spawn_https("tls-a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::https_skip_verify("p", vec![backend.addr])],
        routes: vec![route("/", "p")],
    })
    .await;
    let client = https_client_http1_only();

    let resp = client
        .get(url(proxy.addr, "/hello"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-backend-name")
            .and_then(|v| v.to_str().ok()),
        Some("tls-a")
    );
    let calls = backend.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].path, "/hello");
}

#[tokio::test]
async fn https_upstream_h2_end_to_end() {
    use quik::config::UpstreamHttpVersion;
    let backend = Backend::spawn_https("tls-a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![
            common::Backends::https_skip_verify("p", vec![backend.addr])
                .with_http_version(UpstreamHttpVersion::H2),
        ],
        routes: vec![route("/", "p")],
    })
    .await;
    let client = https_client(); // HTTP/2 by default

    let resp = client
        .get(url(proxy.addr, "/h2/path"))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.version(),
        reqwest::Version::HTTP_2,
        "client should have seen h2"
    );

    let calls = backend.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].version,
        http::Version::HTTP_2,
        "backend should have seen h2 from the proxy"
    );
}

// ── WebSocket upgrade forwarding ────────────────────────────────────────────

#[tokio::test]
async fn websocket_upgrade_proxied_with_bidirectional_echo() {
    use futures::{SinkExt, StreamExt};
    use std::sync::Arc;
    use tokio_tungstenite::Connector;
    use tokio_tungstenite::tungstenite::Message;

    let backend = Backend::spawn_ws_echo("ws-a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("p", vec![backend.addr])],
        routes: vec![route("/", "p")],
    })
    .await;

    // Build a rustls config that accepts the proxy's self-signed cert.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TestNoVerifier))
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let ws_url = format!("wss://localhost:{}/echo", proxy.addr.port());
    let (mut ws, resp) = tokio_tungstenite::connect_async_tls_with_config(
        ws_url,
        None,
        false,
        Some(Connector::Rustls(Arc::new(tls_config))),
    )
    .await
    .expect("ws connect");
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);

    // Exchange a few messages.
    ws.send(Message::Text("hello".into())).await.unwrap();
    let echoed = ws.next().await.unwrap().unwrap();
    assert_eq!(echoed.into_text().unwrap().as_str(), "hello");

    ws.send(Message::Binary(Bytes::from_static(&[
        0xDE, 0xAD, 0xBE, 0xEF,
    ])))
    .await
    .unwrap();
    let echoed = ws.next().await.unwrap().unwrap();
    assert_eq!(&*echoed.into_data(), &[0xDE, 0xAD, 0xBE, 0xEF]);

    ws.close(None).await.unwrap();
}

// Minimal cert verifier used only by the WS test. The general-purpose
// h2 helper has its own; duplicate here to keep the test self-contained.
#[derive(Debug)]
struct TestNoVerifier;

impl rustls::client::danger::ServerCertVerifier for TestNoVerifier {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ── SSE streaming pass-through ──────────────────────────────────────────────

#[tokio::test]
async fn sse_events_arrive_separately_not_buffered() {
    use http_body_util::{BodyExt, Empty};
    use std::time::Instant;

    let backend = Backend::spawn_sse("sse-a", 3, Duration::from_millis(100)).await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::https_skip_verify("p", vec![backend.addr])],
        routes: vec![route("/", "p")],
    })
    .await;

    let client = common::hyper_h2_client();
    let req = http::Request::builder()
        .method("GET")
        .uri(url(proxy.addr, "/stream"))
        .version(http::Version::HTTP_2)
        .body(Empty::<bytes::Bytes>::new())
        .unwrap();

    let resp = client.request(req).await.expect("send");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/event-stream"
    );

    let started = Instant::now();
    let mut body = resp.into_body();
    // Only non-empty data frames count as "events" — h2 sometimes interleaves
    // empty data frames for flow-control / padding which aren't user-visible.
    let mut arrivals: Vec<(Duration, Bytes)> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.expect("frame");
        if let Some(data) = frame.data_ref()
            && !data.is_empty()
        {
            arrivals.push((started.elapsed(), Bytes::copy_from_slice(data)));
        }
    }

    // Backend yields 3 events at 100ms intervals (0ms, 100ms, 200ms).
    assert!(
        arrivals.len() >= 3,
        "expected at least 3 non-empty data frames, got {}",
        arrivals.len()
    );

    // First event must arrive well before the last event would, proving the
    // proxy isn't collecting all frames before flushing.
    let first = arrivals.first().unwrap().0;
    let last = arrivals.last().unwrap().0;
    assert!(
        first < Duration::from_millis(80),
        "first event arrived too late ({first:?}) — proxy is buffering"
    );
    assert!(
        last >= Duration::from_millis(150),
        "last event arrived too quickly ({last:?}) — backend delays not observed end-to-end"
    );
    assert!(
        last - first >= Duration::from_millis(100),
        "spread between first and last event was {:?}, expected ≥100ms",
        last - first
    );

    // Sanity: at least one chunk looks like an SSE event line.
    let any_sse_shape = arrivals.iter().any(|(_, b)| {
        std::str::from_utf8(b)
            .map(|s| s.contains("data:"))
            .unwrap_or(false)
    });
    assert!(any_sse_shape, "no chunk contained an SSE data line");
}

// ── gRPC trailer round-trip ─────────────────────────────────────────────────

#[tokio::test]
async fn grpc_trailers_pass_through_h2() {
    use http_body_util::{BodyExt, Empty};
    use quik::config::UpstreamHttpVersion;

    let backend = Backend::spawn_https("grpc").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![
            common::Backends::https_skip_verify("p", vec![backend.addr])
                .with_http_version(UpstreamHttpVersion::H2),
        ],
        routes: vec![route("/", "p")],
    })
    .await;

    let client = common::hyper_h2_client();
    let target_url = url(proxy.addr, "/grpc/method");

    let req = http::Request::builder()
        .method("POST")
        .uri(&target_url)
        .version(http::Version::HTTP_2)
        .header("content-type", "application/grpc")
        // tell the backend to emit these as response trailers
        .header("x-want-trailers", "grpc-status=0,grpc-message=OK")
        .body(Empty::<bytes::Bytes>::new())
        .unwrap();

    let resp = client.request(req).await.expect("send");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.version(), http::Version::HTTP_2);

    // Drain the body, capturing the trailer frame.
    let mut body = resp.into_body();
    let mut got_data = false;
    let mut trailers: Option<HeaderMap> = None;
    while let Some(frame) = body.frame().await {
        let frame = frame.expect("frame");
        if frame.is_data() {
            got_data = true;
        } else if frame.is_trailers() {
            trailers = Some(frame.into_trailers().unwrap());
        }
    }

    assert!(got_data, "expected at least one data frame");
    let t = trailers.expect("response should carry trailers");
    assert_eq!(t.get("grpc-status").unwrap(), "0");
    assert_eq!(t.get("grpc-message").unwrap(), "OK");
}

#[tokio::test]
async fn stream_body_limit_aborts_oversized_chunked_upload() {
    use futures::stream;

    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("p", vec![backend.addr])],
        routes: vec![RouteConfig {
            path_prefix: Some("/".to_string()),
            max_body_bytes: Some(1024),
            upstream: "p".to_string(),
            ..Default::default()
        }],
    })
    .await;
    let client = https_client_http1_only();

    // Chunked body (no Content-Length) totalling 1.2KB — exceeds the 1024 limit.
    // The Content-Length pre-check can't fire here because there isn't one;
    // the stream-aware wrap is what catches it.
    let chunks = stream::iter(vec![
        Ok::<_, std::io::Error>(Bytes::from(vec![b'x'; 600])),
        Ok::<_, std::io::Error>(Bytes::from(vec![b'x'; 600])),
    ]);
    let body = reqwest::Body::wrap_stream(chunks);

    let resp = client
        .post(url(proxy.addr, "/upload"))
        .body(body)
        .send()
        .await;

    // Either the proxy returned a 5xx (upstream error from broken body stream)
    // or the connection was reset — both indicate the limit was enforced.
    match resp {
        Ok(r) => assert!(
            r.status().is_server_error() || r.status() == StatusCode::PAYLOAD_TOO_LARGE,
            "expected 5xx or 413, got {}",
            r.status()
        ),
        Err(_) => { /* connection reset is acceptable */ }
    }

    // If the backend ever saw the request, it must not have received the full body.
    let calls = backend.calls();
    for c in &calls {
        assert!(
            c.body.len() <= 1024,
            "backend received {} bytes, exceeds limit of 1024",
            c.body.len()
        );
    }
}

#[tokio::test]
async fn body_too_large_returns_413() {
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("p", vec![backend.addr])],
        routes: vec![RouteConfig {
            path_prefix: Some("/".to_string()),
            max_body_bytes: Some(1024),
            upstream: "p".to_string(),
            ..Default::default()
        }],
    })
    .await;
    let client = https_client_http1_only();

    // Body exceeds limit — Content-Length set by reqwest. Expect 413.
    let payload = "x".repeat(2048);
    let resp = client
        .post(url(proxy.addr, "/upload"))
        .body(payload)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(backend.calls().len(), 0, "request should not reach backend");

    // Body under limit — should pass through.
    let small = "x".repeat(512);
    let resp = client
        .post(url(proxy.addr, "/upload"))
        .body(small)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::OK);
}
