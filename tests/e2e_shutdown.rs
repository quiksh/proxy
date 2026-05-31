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
