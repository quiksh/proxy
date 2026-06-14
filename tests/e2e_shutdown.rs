//! Drain behaviour: triggering drain stops the listener from accepting new
//! connections and makes /healthz flip to 503.

mod common;

use std::time::Duration;

use bytes::Bytes;
use http::StatusCode;

use common::{Backend, ProxySpec, https_client, route, spawn_proxy};

#[tokio::test]
async fn listener_stops_accepting_after_drain() {
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("p", vec![backend.addr])],
        routes: vec![route("/", "p")],
    })
    .await;

    let client = https_client();
    let url = format!("https://localhost:{}/ping", proxy.addr.port());

    // baseline: request succeeds
    let resp = client.get(&url).send().await.expect("send");
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = resp.bytes().await;

    proxy.shutdown.trigger_drain();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // After drain, a fresh TCP connection should fail because the listener has
    // stopped accepting. We use a NEW client to force a fresh connection (the
    // previous client may still hold an open pooled connection).
    let fresh_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .connect_timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let res = fresh_client.get(&url).send().await;
    assert!(
        res.is_err(),
        "expected fresh request to fail after drain, got: {res:?}"
    );
}

#[tokio::test]
async fn in_flight_request_completes_after_drain() {
    // A request that is already mid-flight should complete; drain only stops
    // new connections.
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("p", vec![backend.addr])],
        routes: vec![route("/", "p")],
    })
    .await;

    let client = https_client();
    let url = format!("https://localhost:{}/ping", proxy.addr.port());

    // Warm a pooled connection
    let resp = client.get(&url).send().await.expect("warm");
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = resp.bytes().await;

    proxy.shutdown.trigger_drain();

    // Even immediately after triggering drain, a request over the existing
    // connection should still complete (graceful shutdown is bounded by the
    // drain grace period, which is 3s in the test config).
    let resp = client.get(&url).send().await.expect("post-drain");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.bytes().await.expect("body");
    assert!(!body.is_empty());

    // Strict equality on a known field to confirm body actually streamed.
    assert!(body.starts_with(&Bytes::from_static(b"{\"backend\":\"a\"")));
}

#[tokio::test]
async fn pre_drain_withdraws_health_before_listener_stops() {
    // Edge-withdraw ordering. When the pre-drain phase begins,
    // /healthz must flip to 503 *while the proxy keeps accepting* — so a
    // perimeter health check withdraws traffic before in-flight is cut. Only
    // when the actual drain begins should the listener stop accepting.
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![common::Backends::http("p", vec![backend.addr])],
        routes: vec![route("/", "p")],
    })
    .await;

    let proxy_url = format!("https://localhost:{}/ping", proxy.addr.port());
    let healthz = format!("http://{}/healthz", proxy.admin_addr);
    let admin = reqwest::Client::new();

    // Fresh-connection helper so we never reuse a pooled socket — each call
    // genuinely re-tests whether the listener still accepts.
    let fresh = || {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .connect_timeout(Duration::from_secs(2))
            .build()
            .unwrap()
    };

    // Baseline: healthy and serving.
    assert_eq!(
        admin.get(&healthz).send().await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        fresh().get(&proxy_url).send().await.unwrap().status(),
        StatusCode::OK
    );

    // Begin the edge-withdraw phase.
    proxy.shutdown.begin_pre_drain();

    // /healthz now reports 503 …
    assert_eq!(
        admin.get(&healthz).send().await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "healthz must report draining as soon as pre-drain begins"
    );
    // … but the proxy is STILL accepting new connections (the ordering point).
    assert_eq!(
        fresh().get(&proxy_url).send().await.unwrap().status(),
        StatusCode::OK,
        "listener must keep accepting during the edge-withdraw grace"
    );

    // Now the real drain begins → the listener stops accepting.
    proxy.shutdown.trigger_drain();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let res = fresh().get(&proxy_url).send().await;
    assert!(
        res.is_err(),
        "fresh request should fail once the drain phase stops the listener, got: {res:?}"
    );
}
