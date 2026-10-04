//! Outbound HTTP(S) clients for auth: JWKS fetches and external authorizers.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls::ClientConfig;

use crate::config::AuthorizerTlsConfig;
use crate::tls::{parse_certs, parse_key};
use crate::upstream::ProxyClient;

pub(super) fn build_jwks_client() -> ProxyClient {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);
    Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(2)
        .pool_idle_timeout(Duration::from_secs(60))
        .build(https)
}

/// Build a JWKS client that bypasses certificate verification. Only used by
/// the test harness - production code should never call this.
#[doc(hidden)]
pub fn build_jwks_client_skip_verify() -> ProxyClient {
    use rustls::DigitallySignedStruct;
    use rustls::SignatureScheme;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    #[derive(Debug)]
    struct NoVerify;
    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    let tls_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);
    Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(2)
        .build(https)
}

/// Build the client for one `[[authorizers]]` block. Trusts the bundled public
/// roots plus any `tls.ca_path` bundle, and presents a client certificate when
/// `tls.cert_path`/`key_path` are set. Unlike the JWKS client this one is on
/// the request path, so it keeps a larger idle pool to avoid handshakes.
pub(super) fn build_authorizer_client(tls: &AuthorizerTlsConfig) -> Result<ProxyClient> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = &tls.ca_path {
        let pem = std::fs::read(path).with_context(|| format!("reading tls.ca_path '{path}'"))?;
        for cert in parse_certs(&pem).with_context(|| format!("tls.ca_path '{path}'"))? {
            roots
                .add(cert)
                .with_context(|| format!("adding CA from '{path}'"))?;
        }
    }
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let tls_config = match (&tls.cert_path, &tls.key_path) {
        (Some(cert), Some(key)) => {
            let cert_pem =
                std::fs::read(cert).with_context(|| format!("reading tls.cert_path '{cert}'"))?;
            let key_pem =
                std::fs::read(key).with_context(|| format!("reading tls.key_path '{key}'"))?;
            builder
                .with_client_auth_cert(parse_certs(&cert_pem)?, parse_key(&key_pem)?)
                .context("building authorizer client certificate")?
        }
        _ => builder.with_no_client_auth(),
    };
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_nodelay(true);
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);
    Ok(Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(32)
        .pool_idle_timeout(Duration::from_secs(90))
        .build(https))
}
