//! Hardening features: defensive timeouts, WS idle culling, WS drain.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{Backend, Backends, ProxySpec, route, spawn_proxy_with_limits};
use futures::{SinkExt, StreamExt};
use http::StatusCode;
use quik::config::ListenerLimitsConfig;
use tokio_tungstenite::Connector;
use tokio_tungstenite::tungstenite::Message;

// ── WebSocket idle culling ──────────────────────────────────────────────────

#[tokio::test]
async fn websocket_idle_tunnel_is_culled_after_timeout() {
    let backend = Backend::spawn_ws_echo("ws-a").await;
    let limits = ListenerLimitsConfig {
        websocket_idle_timeout_ms: 500,
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

    let (mut ws, resp) = connect_ws(proxy.addr.port()).await;
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);

    // Don't send anything. The proxy should close the tunnel after ~500ms idle.
    // Reading the next frame returns when the underlying transport closes.
    let started = Instant::now();
    let next = tokio::time::timeout(Duration::from_secs(5), ws.next()).await;
    let elapsed = started.elapsed();

    assert!(
        next.is_ok(),
        "ws read did not return within 5s - idle cull did not fire"
    );
    // Idle timeout is 500ms; allow generous wall-clock slack for CI.
    assert!(
        elapsed < Duration::from_secs(3),
        "ws idle cull took too long: {elapsed:?}"
    );
}

// ── WebSocket drain hook ────────────────────────────────────────────────────

#[tokio::test]
async fn websocket_tunnel_closes_on_proxy_drain() {
    let backend = Backend::spawn_ws_echo("ws-b").await;
    let proxy = spawn_proxy_with_limits(
        ProxySpec {
            pools: vec![Backends::http("p", vec![backend.addr])],
            routes: vec![route("/", "p")],
        },
        ListenerLimitsConfig {
            // Disable idle so we know any close is drain-driven.
            websocket_idle_timeout_ms: 0,
            ..Default::default()
        },
    )
    .await;

    let (mut ws, _) = connect_ws(proxy.addr.port()).await;
    // Send + receive once so we know the tunnel is live.
    ws.send(Message::Text("ping".into())).await.unwrap();
    let echoed = ws.next().await.unwrap().unwrap();
    assert_eq!(echoed.into_text().unwrap().as_str(), "ping");

    // Trigger drain on the proxy. The spawned bidirectional task should
    // observe the drain signal and close the tunnel.
    let started = Instant::now();
    proxy.shutdown.trigger_drain();

    // Reading the next frame should return EOF / close within a moment.
    let next = tokio::time::timeout(Duration::from_secs(5), ws.next()).await;
    let elapsed = started.elapsed();
    assert!(next.is_ok(), "ws was not closed within 5s of drain");
    assert!(
        elapsed < Duration::from_secs(2),
        "ws drain close took too long: {elapsed:?}"
    );
}

// ── helpers ─────────────────────────────────────────────────────────────────

async fn connect_ws(
    port: u16,
) -> (
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    http::Response<Option<Vec<u8>>>,
) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TestNoVerifier))
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let ws_url = format!("wss://localhost:{port}/echo");
    tokio_tungstenite::connect_async_tls_with_config(
        ws_url,
        None,
        false,
        Some(Connector::Rustls(Arc::new(tls_config))),
    )
    .await
    .expect("ws connect")
}

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
