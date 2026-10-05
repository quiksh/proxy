//! rustls acceptor for the inbound listener.
//!
//! ALPN advertises `h2` and `http/1.1` so a client can negotiate either -
//! the dispatch between them happens inside hyper-util's auto::Builder, not
//! here. Client auth is intentionally disabled: this is an internet-facing
//! ingress, and per-route auth (JWT) is the supported model.
//!
//! `self_signed = true` swaps the on-disk cert for an ephemeral one generated at
//! boot - for sitting behind a load balancer that re-encrypts to its targets
//! without verifying them (AWS ALB/NLB), so there is no key file to manage.
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
    if cfg.self_signed {
        let (cert_pem, key_pem) = generate_self_signed()?;
        tracing::warn!(
            "listener is using an ephemeral self-signed certificate - only suitable behind a \
             load balancer that does not verify target certificates"
        );
        return build_acceptor_from_pem(&cert_pem, &key_pem);
    }
    let (Some(cert_path), Some(key_path)) = (&cfg.cert_path, &cfg.key_path) else {
        return Err(anyhow!(
            "[listener.tls] needs cert_path and key_path, or self_signed = true"
        ));
    };
    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("reading cert file {}", cert_path.display()))?;
    let key_pem = std::fs::read(key_path)
        .with_context(|| format!("reading key file {}", key_path.display()))?;
    build_acceptor_from_pem(&cert_pem, &key_pem)
}

/// A fresh P-256 key and self-signed certificate for `localhost`, held only in
/// memory. Regenerated on every boot, so there is nothing to rotate or leak
/// from the image or disk.
fn generate_self_signed() -> Result<(Vec<u8>, Vec<u8>)> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .context("generating self-signed key")?;
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .context("self-signed certificate params")?
        .self_signed(&key)
        .context("self-signing certificate")?;
    Ok((cert.pem().into_bytes(), key.serialize_pem().into_bytes()))
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

pub(crate) fn parse_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(pem);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.context("parsing certificate PEM")?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates found in PEM"));
    }
    Ok(certs)
}

pub(crate) fn parse_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(pem);
    rustls_pemfile::private_key(&mut reader)
        .context("parsing private key PEM")?
        .ok_or_else(|| anyhow!("no private key found in PEM"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_listener_builds_without_files() {
        let cfg = TlsConfig {
            cert_path: None,
            key_path: None,
            self_signed: true,
        };
        build_acceptor(&cfg).expect("self-signed acceptor");
    }

    #[test]
    fn missing_paths_without_self_signed_is_an_error() {
        let cfg = TlsConfig {
            cert_path: None,
            key_path: None,
            self_signed: false,
        };
        assert!(build_acceptor(&cfg).is_err());
    }
}
