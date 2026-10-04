//! Upstream pool TLS: private CA pinning, mTLS client certs, server-name
//! override - for proxied routes and for pooled authorizers.

mod common;

use std::net::SocketAddr;

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::Full;
use quik::config::{AuthorizerConfig, AuthorizerOnError, RouteConfig, UpstreamTlsConfig};

use common::pki::{Pki, spawn_tls_server};
use common::{ProxySpec, https_client_http1_only};

fn url(proxy: SocketAddr, path: &str) -> String {
    format!("https://localhost:{}{}", proxy.port(), path)
}

fn ok(body: &'static str) -> Response<Full<Bytes>> {
    Response::new(Full::new(Bytes::from_static(body.as_bytes())))
}

/// Full mTLS settings against `pki`.
fn mtls(pki: &Pki) -> UpstreamTlsConfig {
    UpstreamTlsConfig {
        ca_path: Some(pki.ca_path.clone()),
        cert_path: Some(pki.client_cert_path.clone()),
        key_path: Some(pki.client_key_path.clone()),
        server_name: Some("authz.internal".into()),
        ..Default::default()
    }
}

/// Proxy one route `/` to an HTTPS pool with `tls`; return the status.
async fn status_via(member: SocketAddr, tls: UpstreamTlsConfig) -> StatusCode {
    let proxy = common::spawn_proxy(ProxySpec {
        pools: vec![common::Backends::https_tls("p", vec![member], tls)],
        routes: vec![common::route("/", "p")],
    })
    .await;
    https_client_http1_only()
        .get(url(proxy.addr, "/x"))
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn mtls_with_private_ca_and_client_cert_succeeds() {
    let pki = Pki::new();
    let member = spawn_tls_server(pki.acceptor(true), |_| ok("hello")).await;
    assert_eq!(status_via(member, mtls(&pki)).await, StatusCode::OK);
}

#[tokio::test]
async fn missing_client_cert_is_rejected_by_server() {
    let pki = Pki::new();
    let member = spawn_tls_server(pki.acceptor(true), |_| ok("hello")).await;
    let tls = UpstreamTlsConfig {
        cert_path: None,
        key_path: None,
        ..mtls(&pki)
    };
    assert_eq!(status_via(member, tls).await, StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn client_cert_from_another_ca_is_rejected_by_server() {
    let pki = Pki::new();
    let member = spawn_tls_server(pki.acceptor(true), |_| ok("hello")).await;
    let tls = UpstreamTlsConfig {
        cert_path: Some(pki.rogue_client_cert_path.clone()),
        key_path: Some(pki.rogue_client_key_path.clone()),
        ..mtls(&pki)
    };
    assert_eq!(status_via(member, tls).await, StatusCode::BAD_GATEWAY);
}

/// SECURITY: `ca_path` pins the pool to that CA - a server cert from any
/// other CA (including the public roots) is refused.
#[tokio::test]
async fn server_cert_not_from_pinned_ca_is_refused() {
    let pki = Pki::new();
    let member = spawn_tls_server(pki.acceptor(false), |_| ok("hello")).await;
    let tls = UpstreamTlsConfig {
        ca_path: Some(pki.other_ca_path.clone()),
        ..mtls(&pki)
    };
    assert_eq!(status_via(member, tls).await, StatusCode::BAD_GATEWAY);

    // Public roots only (no ca_path): a private-CA cert is untrusted too.
    let tls = UpstreamTlsConfig {
        ca_path: None,
        ..mtls(&pki)
    };
    assert_eq!(status_via(member, tls).await, StatusCode::BAD_GATEWAY);
}

/// Members are addressed by IP but the cert names `authz.internal`:
/// verification needs `server_name`.
#[tokio::test]
async fn server_name_override_is_required_for_ip_members() {
    let pki = Pki::new();
    let member = spawn_tls_server(pki.acceptor(false), |_| ok("hello")).await;
    let without = UpstreamTlsConfig {
        server_name: None,
        ..mtls(&pki)
    };
    assert_eq!(status_via(member, without).await, StatusCode::BAD_GATEWAY);
    assert_eq!(status_via(member, mtls(&pki)).await, StatusCode::OK);
}

/// The headline use case: a pooled authorizer reached over mutual TLS.
#[tokio::test]
async fn pooled_authorizer_over_mtls() {
    let pki = Pki::new();
    let authz = spawn_tls_server(pki.acceptor(true), |req| {
        assert_eq!(req.uri().path(), "/v1/authorize");
        let mut r = Response::new(Full::new(Bytes::from_static(
            br#"{"headers":{"x-user-id":"u_mtls"}}"#,
        )));
        r.headers_mut()
            .insert("content-type", "application/json".parse().unwrap());
        r
    })
    .await;
    let backend = common::Backend::spawn("a").await;
    let proxy = common::spawn_proxy_with_authorizers(
        ProxySpec {
            pools: vec![
                common::Backends::http("p", vec![backend.addr]),
                common::Backends::https_tls("authz", vec![authz], mtls(&pki)),
            ],
            routes: vec![RouteConfig {
                path_prefix: Some("/".to_string()),
                authorizer: Some("internal".to_string()),
                upstream: "p".to_string(),
                ..Default::default()
            }],
        },
        vec![],
        vec![AuthorizerConfig {
            name: "internal".into(),
            url: None,
            upstream: Some("authz".into()),
            path: Some("/v1/authorize".into()),
            retries: 1,
            timeout_ms: 2000,
            forward_headers: vec![],
            inject_headers: vec!["x-user-id".into()],
            on_error: AuthorizerOnError::Deny,
            include_body: false,
            max_body_bytes: 1024,
            body_timeout_ms: 1000,
            tls: Default::default(),
            cache: Default::default(),
        }],
    )
    .await;

    let resp = https_client_http1_only()
        .get(url(proxy.addr, "/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        backend.calls()[0].headers.get("x-user-id").unwrap(),
        "u_mtls"
    );
}
