//! Throwaway private PKI for mTLS tests: a CA, a server cert (SAN
//! `authz.internal` only - no IP SAN, so connecting by IP needs quik's
//! `tls.server_name`) and a client cert signed by it,
//! plus an unrelated CA for "wrong CA" cases. Files are written to a unique
//! temp directory because quik's config takes paths.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperServer;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub struct Pki {
    pub dir: PathBuf,
    pub ca_pem: String,
    server_cert_pem: String,
    server_key_der: Vec<u8>,
    /// Paths quik's config can point at.
    pub ca_path: String,
    pub client_cert_path: String,
    pub client_key_path: String,
    /// A CA that signed nothing here - trusting it must fail verification.
    pub other_ca_path: String,
    /// A client cert from the *other* CA - the server must reject it.
    pub rogue_client_cert_path: String,
    pub rogue_client_key_path: String,
}

fn ca(name: &str) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.distinguished_name.push(DnType::CommonName, name);
    (p.self_signed(&key).unwrap(), key)
}

fn leaf(
    sans: &[&str],
    ips: &[&str],
    usage: ExtendedKeyUsagePurpose,
    issuer: &rcgen::Certificate,
    issuer_key: &KeyPair,
) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut p =
        CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
    for ip in ips {
        p.subject_alt_names
            .push(SanType::IpAddress(ip.parse().unwrap()));
    }
    p.extended_key_usages = vec![usage];
    (p.signed_by(&key, issuer, issuer_key).unwrap(), key)
}

static SEQ: AtomicU64 = AtomicU64::new(0);

impl Pki {
    pub fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "quik-pki-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let write = |name: &str, body: &str| {
            let p = dir.join(name);
            std::fs::write(&p, body).unwrap();
            p.to_string_lossy().into_owned()
        };

        let (ca_cert, ca_key) = ca("quik test ca");
        let (srv, srv_key) = leaf(
            &["authz.internal"],
            &[],
            ExtendedKeyUsagePurpose::ServerAuth,
            &ca_cert,
            &ca_key,
        );
        let (cli, cli_key) = leaf(
            &["quik-edge"],
            &[],
            ExtendedKeyUsagePurpose::ClientAuth,
            &ca_cert,
            &ca_key,
        );
        let (other_ca, other_key) = ca("unrelated ca");
        let (rogue, rogue_key) = leaf(
            &["rogue"],
            &[],
            ExtendedKeyUsagePurpose::ClientAuth,
            &other_ca,
            &other_key,
        );

        Self {
            ca_path: write("ca.pem", &ca_cert.pem()),
            client_cert_path: write("client.pem", &cli.pem()),
            client_key_path: write("client.key", &cli_key.serialize_pem()),
            other_ca_path: write("other-ca.pem", &other_ca.pem()),
            rogue_client_cert_path: write("rogue.pem", &rogue.pem()),
            rogue_client_key_path: write("rogue.key", &rogue_key.serialize_pem()),
            ca_pem: ca_cert.pem(),
            server_cert_pem: srv.pem(),
            server_key_der: srv_key.serialize_der(),
            dir,
        }
    }

    /// A TLS acceptor presenting the server cert. With `require_client_cert`,
    /// clients must present a cert chaining to this PKI's CA.
    pub fn acceptor(&self, require_client_cert: bool) -> TlsAcceptor {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut self.server_cert_pem.as_bytes())
                .collect::<Result<_, _>>()
                .unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.server_key_der.clone()));
        let builder = rustls::ServerConfig::builder();
        let builder = if require_client_cert {
            let mut roots = rustls::RootCertStore::empty();
            for c in rustls_pemfile::certs(&mut self.ca_pem.as_bytes()) {
                roots.add(c.unwrap()).unwrap();
            }
            builder.with_client_cert_verifier(
                WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .unwrap(),
            )
        } else {
            builder.with_no_client_auth()
        };
        let mut cfg = builder.with_single_cert(certs, key).unwrap();
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        TlsAcceptor::from(Arc::new(cfg))
    }
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Serve `handler` over TLS from `acceptor` on an ephemeral port. Failed
/// handshakes (e.g. a missing client cert) just drop the connection.
pub async fn spawn_tls_server<F>(acceptor: TlsAcceptor, handler: F) -> SocketAddr
where
    F: Fn(Request<Incoming>) -> Response<Full<Bytes>> + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let handler = handler.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = service_fn(move |req: Request<Incoming>| {
                    let handler = handler.clone();
                    async move { Ok::<_, Infallible>(handler(req)) }
                });
                let _ = HyperServer::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    addr
}
