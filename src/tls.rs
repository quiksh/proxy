//! rustls acceptor for the inbound listener.
//!
//! ALPN advertises `h2` and `http/1.1` so a client can negotiate either —
//! the dispatch between them happens inside hyper-util's auto::Builder, not
//! here. Client auth is intentionally disabled: this is an internet-facing
//! ingress, and per-route auth (JWT) is the supported model.
//!
//! The aws-lc-rs crypto provider is installed lazily on first call;
//! subsequent calls to `install_default` are idempotent no-ops.

use std::io::BufReader;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

use crate::config::TlsConfig;

pub fn build_acceptor(cfg: &TlsConfig) -> Result<TlsAcceptor> {
    let cert_pem = std::fs::read(&cfg.cert_path)
        .with_context(|| format!("reading cert file {}", cfg.cert_path.display()))?;
    let key_pem = std::fs::read(&cfg.key_path)
        .with_context(|| format!("reading key file {}", cfg.key_path.display()))?;
    build_acceptor_from_pem(&cert_pem, &key_pem)
}

pub fn build_acceptor_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<TlsAcceptor> {
    // install_default returns Err if a provider is already installed (idempotent).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let certs = parse_certs(cert_pem)?;
    let key = parse_key(key_pem)?;

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building rustls ServerConfig")?;

    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

fn parse_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(pem);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.context("parsing certificate PEM")?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates found in PEM"));
    }
    Ok(certs)
}

fn parse_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(pem);
    rustls_pemfile::private_key(&mut reader)
        .context("parsing private key PEM")?
        .ok_or_else(|| anyhow!("no private key found in PEM"))
}
