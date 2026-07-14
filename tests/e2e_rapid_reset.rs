//! Rapid Reset (CVE-2023-44487) mitigation e2e.
//!
//! Verifies that `http2_max_pending_accept_reset_streams` is actually plumbed
//! into the inbound hyper builder: a client that opens HTTP/2 streams and
//! immediately RSTs them should trip the pending-accept-reset budget and get
//! GOAWAY(ENHANCE_YOUR_CALM), closing the connection.
//!
//! **CI-skipped, run locally.** GitHub Actions sets `CI=true`, and this test
//! bails out early there - it drives a tight RST_STREAM burst whose timing is
//! sensitive to the accept loop scheduling, which is exactly the kind of thing
//! that flakes on shared CI runners. A normal local `make test` / `cargo test`
//! runs it (no `CI` env var); force it in a CI-like shell with `CI= ` unset.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{Backend, Backends, ProxySpec, TestNoVerifier, route, spawn_proxy_with_limits};
use quik::config::ListenerLimitsConfig;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Number of open+reset cycles to fire. Far above the configured budget (5)
/// for margin, but well under the default `max_concurrent_streams` (256) - so
/// we trip the reset budget, never the concurrency cap. `#[tokio::test]` is a
/// current-thread runtime and the send loop never awaits, so the spawned
/// connection driver cannot interleave: all 150 HEADERS+RST frames are queued
/// before the server accepts any, which is the deterministic rapid-reset shape.
const BURST: usize = 150;
const RESET_BUDGET: usize = 5;

#[tokio::test]
async fn rapid_reset_burst_triggers_goaway() {
    if std::env::var_os("CI").is_some() {
        eprintln!("skipping rapid-reset e2e under CI (set no CI env var to run locally)");
        return;
    }

    let backend = Backend::spawn("rr").await;
    let limits = ListenerLimitsConfig {
        http2_max_pending_accept_reset_streams: RESET_BUDGET,
        ..Default::default()
    };
    let proxy = spawn_proxy_with_limits(
        ProxySpec {
            pools: vec![Backends::http("p", vec![backend.addr])],
            routes: vec![route("/", "p")],
        },
        limits,
    )
    .await;

    // TLS connect to the proxy, negotiating h2 via ALPN.
    let tls = h2_tls_connect(proxy.addr).await;
    let (mut send_req, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
    let driver = tokio::spawn(connection);

    // Fire the burst: open a stream, immediately RST it. Synchronous loop with
    // no await between iterations, so the frames go out as one burst before the
    // proxy's accept loop can drain them - the rapid-reset signature.
    for _ in 0..BURST {
        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri("https://localhost/")
            .body(())
            .unwrap();
        match send_req.send_request(req, true) {
            Ok((_resp, mut stream)) => stream.send_reset(h2::Reason::CANCEL),
            // Server already refused / went away mid-burst - that's the win.
            Err(_) => break,
        }
    }

    // The server should tear the connection down with GOAWAY. The connection
    // driver then resolves to Err. If the knob weren't plumbed, the server
    // would happily absorb every reset and the driver would idle until timeout.
    let result = tokio::time::timeout(Duration::from_secs(5), driver)
        .await
        .expect("connection driver did not resolve within 5s - no GOAWAY, mitigation not firing")
        .expect("connection driver task panicked");

    let err = result.expect_err("server kept the connection open despite the rapid-reset burst");
    // Insist on the specific rapid-reset GOAWAY. A connection that died for any
    // other reason (TCP RST, unrelated IO error, a different h2 error carrying
    // no reason) must NOT count as the mitigation firing.
    assert_eq!(
        err.reason(),
        Some(h2::Reason::ENHANCE_YOUR_CALM),
        "expected GOAWAY(ENHANCE_YOUR_CALM), got: {err:?}"
    );
}

/// Open a TCP+TLS connection to `addr` with ALPN offering only `h2`, accepting
/// the proxy's self-signed cert.
async fn h2_tls_connect(addr: std::net::SocketAddr) -> tokio_rustls::client::TlsStream<TcpStream> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TestNoVerifier))
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h2".to_vec()];

    let connector = TlsConnector::from(Arc::new(tls_config));
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect")
}
