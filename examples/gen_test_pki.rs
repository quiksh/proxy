//! Generate a throwaway private PKI for local mTLS testing and benchmarks.
//!
//! ```bash
//! cargo run --example gen_test_pki -- ./tls/pki
//! ```
//!
//! Writes into the target directory:
//!   ca.pem                     - the CA (trust this on both sides)
//!   server.pem / server.key    - server cert, SANs `authz.internal`, `localhost`, 127.0.0.1
//!   client.pem / client.key    - client cert for quik (mTLS)
//!
//! Test material only: keys are unencrypted and the CA has no constraints.

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType,
};

fn main() -> Result<()> {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "./tls/pki".into());
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {dir}"))?;
    let write = |name: &str, body: String| -> Result<()> {
        std::fs::write(format!("{dir}/{name}"), body).with_context(|| format!("writing {name}"))
    };

    let ca_key = KeyPair::generate()?;
    let mut ca = CertificateParams::new(Vec::<String>::new())?;
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.distinguished_name
        .push(DnType::CommonName, "quik test CA");
    let ca = ca.self_signed(&ca_key)?;

    let srv_key = KeyPair::generate()?;
    let mut srv = CertificateParams::new(vec!["authz.internal".into(), "localhost".into()])?;
    srv.subject_alt_names
        .push(SanType::IpAddress("127.0.0.1".parse()?));
    srv.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let srv = srv.signed_by(&srv_key, &ca, &ca_key)?;

    let cli_key = KeyPair::generate()?;
    let mut cli = CertificateParams::new(vec!["quik-edge".into()])?;
    cli.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cli = cli.signed_by(&cli_key, &ca, &ca_key)?;

    write("ca.pem", ca.pem())?;
    write("server.pem", srv.pem())?;
    write("server.key", srv_key.serialize_pem())?;
    write("client.pem", cli.pem())?;
    write("client.key", cli_key.serialize_pem())?;
    eprintln!("wrote test PKI to {dir}");
    Ok(())
}
