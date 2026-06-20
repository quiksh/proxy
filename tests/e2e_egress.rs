//! Egress (forward) proxy end-to-end tests.
//!
//! Spins up the egress listener directly (no full quik startup), drives
//! it via raw TCP with hand-formed CONNECT requests, and asserts the
//! tunnel behaviour. Uses the shared test echo backend as the destination
//! once a tunnel is established.

mod common;

use std::sync::Arc;
use std::time::Duration;

use quik::config::{EgressAction, EgressConfig, EgressRuleConfig};
use quik::egress::EgressPolicy;
use quik::shutdown::Coordinator;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use common::Backend;

/// Spawn the egress listener directly and return its bound address.
async fn spawn_egress(rules: Vec<EgressRuleConfig>, default: EgressAction) -> std::net::SocketAddr {
    // Ensure the prometheus recorder is installed (egress counter handles
    // need it before construction, same hazard as the upstream pool).
    common::install_metrics_recorder();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let cfg = EgressConfig {
        bind: addr,
        default_action: default,
        sni_enforce: false,
        rules,
        auth: None,
    };
    let policy = Arc::new(EgressPolicy::from_config(&cfg).expect("compile policy"));
    let shutdown = Coordinator::new(2, 0);

    tokio::spawn(quik::egress::serve(listener, policy, shutdown));
    addr
}

/// Read up to `n` bytes from `stream` with a short timeout, returning the
/// portion actually read as UTF-8 (or replacement characters for bytes
/// that aren't valid UTF-8 - fine for HTTP response sniffing).
async fn read_some(stream: &mut TcpStream, n: usize) -> String {
    let mut buf = vec![0u8; n];
    let got = match tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
        Ok(Ok(read)) => read,
        _ => 0,
    };
    String::from_utf8_lossy(&buf[..got]).into_owned()
}

#[tokio::test]
async fn egress_allows_destination_that_matches_a_cidr_rule() {
    let dest = Backend::spawn("dest").await;

    // Allow anything in 127.0.0.0/8 - covers our test backend on localhost.
    let egress_addr = spawn_egress(
        vec![EgressRuleConfig {
            action: EgressAction::Allow,
            hosts: vec![],
            cidrs: vec!["127.0.0.0/8".to_string()],
        }],
        EgressAction::Deny,
    )
    .await;

    let mut tunnel = TcpStream::connect(egress_addr)
        .await
        .expect("connect egress");

    // CONNECT to the destination backend.
    let connect = format!(
        "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n",
        port = dest.addr.port()
    );
    tunnel.write_all(connect.as_bytes()).await.unwrap();
    let resp = read_some(&mut tunnel, 128).await;
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "expected 200 Connection Established, got: {resp:?}"
    );

    // Now use the tunnel as a plain pipe to the destination - send an HTTP
    // request through it and confirm the backend saw it.
    let inner = "GET /hello HTTP/1.1\r\nHost: dest\r\nConnection: close\r\n\r\n";
    tunnel.write_all(inner.as_bytes()).await.unwrap();
    let resp = read_some(&mut tunnel, 4096).await;
    assert!(
        resp.contains("200") && resp.contains("dest"),
        "expected 200 from echo backend through the tunnel, got: {resp:?}"
    );

    // Backend should have recorded the request.
    let calls = dest.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].path, "/hello");
}

#[tokio::test]
async fn egress_denies_destination_not_covered_by_any_rule() {
    let dest = Backend::spawn("dest").await;
    // Default-deny, no rules → every CONNECT gets refused.
    let egress_addr = spawn_egress(vec![], EgressAction::Deny).await;

    let mut tunnel = TcpStream::connect(egress_addr).await.unwrap();
    let connect = format!(
        "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n",
        port = dest.addr.port()
    );
    tunnel.write_all(connect.as_bytes()).await.unwrap();

    let resp = read_some(&mut tunnel, 256).await;
    assert!(
        resp.starts_with("HTTP/1.1 403"),
        "expected 403 Forbidden, got: {resp:?}"
    );
    assert_eq!(
        dest.calls().len(),
        0,
        "backend must not have been hit when policy denies"
    );
}

#[tokio::test]
async fn egress_deny_does_not_label_metric_by_caller_target() {
    // A denied target is caller-controlled and unbounded. It must NOT become a
    // metric label value (a cardinality DoS - one series per bogus host). The
    // deny path counts with target="-"; the host only lives in the access log.
    let egress_addr = spawn_egress(vec![], EgressAction::Deny).await;

    // A unique, unroutable target no other test uses (RFC 5737 TEST-NET-2).
    let probe = "198.51.100.7:443";
    let mut tunnel = TcpStream::connect(egress_addr).await.unwrap();
    let connect = format!("CONNECT {probe} HTTP/1.1\r\nHost: {probe}\r\n\r\n");
    tunnel.write_all(connect.as_bytes()).await.unwrap();
    let resp = read_some(&mut tunnel, 256).await;
    assert!(
        resp.starts_with("HTTP/1.1 403"),
        "expected 403, got: {resp:?}"
    );

    // The metric is incremented synchronously before the 403 is returned, so
    // by now it's recorded. Render the shared registry and check the label.
    let rendered = common::shared_metrics_handle().render();
    assert!(
        !rendered.contains("198.51.100.7"),
        "denied caller target leaked into a metric label:\n{rendered}"
    );
    assert!(
        rendered
            .lines()
            .any(|l| l.contains("quik_egress_connects_total")
                && l.contains("action=\"deny\"")
                && l.contains("target=\"-\"")),
        "deny should be counted with target=\"-\":\n{rendered}"
    );
}

#[tokio::test]
async fn egress_denies_specific_rule_wins_over_default_allow() {
    let dest = Backend::spawn("dest").await;
    // Default-allow, but deny 127.0.0.0/8 specifically.
    let egress_addr = spawn_egress(
        vec![EgressRuleConfig {
            action: EgressAction::Deny,
            hosts: vec![],
            cidrs: vec!["127.0.0.0/8".to_string()],
        }],
        EgressAction::Allow,
    )
    .await;

    let mut tunnel = TcpStream::connect(egress_addr).await.unwrap();
    let connect = format!(
        "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n",
        port = dest.addr.port()
    );
    tunnel.write_all(connect.as_bytes()).await.unwrap();

    let resp = read_some(&mut tunnel, 256).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "got: {resp:?}");
}

#[tokio::test]
async fn egress_basic_log_only_requires_proxy_authorization() {
    use quik::config::{EgressAuthConfig, EgressConfig};
    use quik::egress::EgressPolicy;
    use quik::shutdown::Coordinator;

    common::install_metrics_recorder();
    let dest = Backend::spawn("dest").await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let egress_addr = listener.local_addr().unwrap();
    let cfg = EgressConfig {
        bind: egress_addr,
        default_action: EgressAction::Allow,
        sni_enforce: false,
        rules: vec![],
        auth: Some(EgressAuthConfig::BasicLogOnly {
            realm: "test".to_string(),
        }),
    };
    let policy = Arc::new(
        EgressPolicy::from_config_with_auth(&cfg, &quik::auth::AuthRegistry::empty()).unwrap(),
    );
    let shutdown = Coordinator::new(2, 0);
    tokio::spawn(quik::egress::serve(listener, policy, shutdown));

    // No Proxy-Authorization → 407 challenge.
    let mut tunnel = TcpStream::connect(egress_addr).await.unwrap();
    let req = format!(
        "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n",
        port = dest.addr.port()
    );
    tunnel.write_all(req.as_bytes()).await.unwrap();
    let resp = read_some(&mut tunnel, 512).await;
    assert!(
        resp.starts_with("HTTP/1.1 407"),
        "expected 407 Proxy Authentication Required, got: {resp:?}"
    );
    assert!(
        resp.to_lowercase().contains("proxy-authenticate: basic"),
        "challenge should advertise Basic, got: {resp:?}"
    );

    // With a Proxy-Authorization header → allowed; the username is recorded
    // (we don't validate the password - pure audit-trail mode).
    use base64::Engine;
    let creds = base64::engine::general_purpose::STANDARD.encode(b"alice:whatever");
    let mut tunnel = TcpStream::connect(egress_addr).await.unwrap();
    let req = format!(
        "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
         Proxy-Authorization: Basic {creds}\r\n\r\n",
        port = dest.addr.port()
    );
    tunnel.write_all(req.as_bytes()).await.unwrap();
    let resp = read_some(&mut tunnel, 256).await;
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "expected 200 Connection Established with valid Basic creds, got: {resp:?}"
    );
}

#[tokio::test]
async fn egress_rejects_non_connect_methods() {
    let egress_addr = spawn_egress(vec![], EgressAction::Allow).await;
    let mut tunnel = TcpStream::connect(egress_addr).await.unwrap();
    tunnel
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let resp = read_some(&mut tunnel, 256).await;
    assert!(
        resp.starts_with("HTTP/1.1 405"),
        "expected 405 Method Not Allowed, got: {resp:?}"
    );
}
