//! Admin API authentication - bearer token and mTLS.
//!
//! Configured per endpoint group (read vs write). Tokens are resolved from
//! env vars at startup, not at request time, so a misconfigured env var
//! fails fast on boot. mTLS verification happens at TLS handshake time
//! (rustls's `WebPkiClientVerifier`); this module just records the verified
//! cert's fingerprint for the audit log.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use http::{HeaderMap, header::AUTHORIZATION};
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};

use crate::config::{AdminAuthConfig, AdminAuthGroups};

/// Resolved auth configuration for one endpoint group, with secrets read in
/// from env at startup.
#[derive(Clone)]
pub enum CompiledAuth {
    /// No auth - endpoint is open.
    None,
    /// Bearer token comparison. The token bytes are kept as `Arc<[u8]>` so
    /// the handler can do constant-time comparison without cloning.
    BearerToken { token: Arc<[u8]> },
    /// mTLS - the TLS handshake guarantees the client cert validated against
    /// the configured CA. The handler reads the fingerprint from the
    /// AuthContext (filled in by the TLS-accepting code) for audit logging.
    Mtls,
}

impl std::fmt::Debug for CompiledAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompiledAuth::None => f.write_str("None"),
            CompiledAuth::BearerToken { .. } => f.write_str("BearerToken{..}"),
            CompiledAuth::Mtls => f.write_str("Mtls"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CompiledAuthGroups {
    pub read: CompiledAuth,
    pub write: CompiledAuth,
}

impl CompiledAuthGroups {
    /// True iff any group uses mTLS - implies the admin listener must run TLS.
    pub fn requires_mtls(&self) -> bool {
        matches!(self.read, CompiledAuth::Mtls) || matches!(self.write, CompiledAuth::Mtls)
    }

    /// True iff any group uses TLS at all (mTLS or via [admin.tls] for
    /// non-mtls modes - but bearer-over-TLS isn't explicitly modelled; the
    /// listener uses TLS only when mtls is in play).
    pub fn requires_tls(&self) -> bool {
        self.requires_mtls()
    }
}

pub fn compile(groups: &AdminAuthGroups) -> Result<CompiledAuthGroups> {
    Ok(CompiledAuthGroups {
        read: compile_one(&groups.read, "admin.auth.read")?,
        write: compile_one(&groups.write, "admin.auth.write")?,
    })
}

fn compile_one(cfg: &AdminAuthConfig, label: &str) -> Result<CompiledAuth> {
    match cfg {
        AdminAuthConfig::None => Ok(CompiledAuth::None),
        AdminAuthConfig::BearerToken { token_env } => {
            let token = std::env::var(token_env).with_context(|| {
                format!(
                    "{label}: bearer_token requires env var '{token_env}' \
                     to be set with the admin token"
                )
            })?;
            if token.is_empty() {
                return Err(anyhow!(
                    "{label}: env var '{token_env}' is set but empty - \
                     bearer token must be non-empty"
                ));
            }
            Ok(CompiledAuth::BearerToken {
                token: token.into_bytes().into(),
            })
        }
        AdminAuthConfig::Mtls => Ok(CompiledAuth::Mtls),
    }
}

/// Group this request belongs to - determined by method.
#[derive(Debug, Clone, Copy)]
pub enum AuthGroup {
    Read,
    Write,
}

/// Per-request authentication context. Built by the listener (per-connection
/// for TLS info, per-request for headers).
pub struct AuthContext<'a> {
    pub group: AuthGroup,
    pub headers: &'a HeaderMap,
    pub peer_cert: Option<&'a CertificateDer<'static>>,
}

#[derive(Debug)]
pub enum AuthFailure {
    MissingToken,
    WrongToken,
    NoClientCert,
    ClientCertInvalid,
}

impl AuthFailure {
    pub fn reason(&self) -> &'static str {
        match self {
            AuthFailure::MissingToken => "missing_token",
            AuthFailure::WrongToken => "wrong_token",
            AuthFailure::NoClientCert => "no_client_cert",
            AuthFailure::ClientCertInvalid => "client_cert_invalid",
        }
    }
}

/// Verify an admin request against the compiled auth groups.
/// On success returns the principal string for audit logging.
pub fn authorize(
    groups: &CompiledAuthGroups,
    ctx: &AuthContext<'_>,
) -> Result<String, AuthFailure> {
    let auth = match ctx.group {
        AuthGroup::Read => &groups.read,
        AuthGroup::Write => &groups.write,
    };
    match auth {
        CompiledAuth::None => Ok("anonymous".to_string()),
        CompiledAuth::BearerToken { token } => verify_bearer(ctx.headers, token),
        CompiledAuth::Mtls => verify_mtls(ctx.peer_cert),
    }
}

fn verify_bearer(headers: &HeaderMap, expected: &[u8]) -> Result<String, AuthFailure> {
    let v = headers
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or(AuthFailure::MissingToken)?;
    let token = v
        .strip_prefix("Bearer ")
        .or_else(|| v.strip_prefix("bearer "))
        .ok_or(AuthFailure::MissingToken)?;
    if token.is_empty() {
        return Err(AuthFailure::MissingToken);
    }
    if constant_time_eq(token.as_bytes(), expected) {
        Ok("bearer:configured".to_string())
    } else {
        Err(AuthFailure::WrongToken)
    }
}

fn verify_mtls(cert: Option<&CertificateDer<'static>>) -> Result<String, AuthFailure> {
    // The TLS layer's `WebPkiClientVerifier` has already validated the cert
    // against the configured CA before we get here. If `peer_cert` is None
    // it means either the client didn't send one (rustls would normally
    // reject the handshake, but defence-in-depth) or the auth group was
    // upgraded to mtls after the connection was accepted.
    let der = cert.ok_or(AuthFailure::NoClientCert)?;
    let fp = cert_fingerprint_hex(der.as_ref());
    Ok(format!("mtls:sha256:{fp}"))
}

fn cert_fingerprint_hex(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest.iter() {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// Constant-time byte comparison. Length-stable to within a few cycles -
/// good enough for an admin token that's not high-volume.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn bearer_accepts_correct_token() {
        let groups = CompiledAuthGroups {
            read: CompiledAuth::None,
            write: CompiledAuth::BearerToken {
                token: b"sekrit".as_slice().into(),
            },
        };
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, HeaderValue::from_static("Bearer sekrit"));
        let ctx = AuthContext {
            group: AuthGroup::Write,
            headers: &h,
            peer_cert: None,
        };
        assert_eq!(authorize(&groups, &ctx).unwrap(), "bearer:configured");
    }

    #[test]
    fn bearer_rejects_wrong_token() {
        let groups = CompiledAuthGroups {
            read: CompiledAuth::None,
            write: CompiledAuth::BearerToken {
                token: b"sekrit".as_slice().into(),
            },
        };
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, HeaderValue::from_static("Bearer wrong"));
        let ctx = AuthContext {
            group: AuthGroup::Write,
            headers: &h,
            peer_cert: None,
        };
        let err = authorize(&groups, &ctx).unwrap_err();
        assert!(matches!(err, AuthFailure::WrongToken));
    }

    #[test]
    fn bearer_missing_header_rejects() {
        let groups = CompiledAuthGroups {
            read: CompiledAuth::None,
            write: CompiledAuth::BearerToken {
                token: b"sekrit".as_slice().into(),
            },
        };
        let h = HeaderMap::new();
        let ctx = AuthContext {
            group: AuthGroup::Write,
            headers: &h,
            peer_cert: None,
        };
        let err = authorize(&groups, &ctx).unwrap_err();
        assert!(matches!(err, AuthFailure::MissingToken));
    }

    #[test]
    fn read_none_lets_anyone_through() {
        let groups = CompiledAuthGroups {
            read: CompiledAuth::None,
            write: CompiledAuth::BearerToken {
                token: b"sekrit".as_slice().into(),
            },
        };
        let h = HeaderMap::new();
        let ctx = AuthContext {
            group: AuthGroup::Read,
            headers: &h,
            peer_cert: None,
        };
        assert_eq!(authorize(&groups, &ctx).unwrap(), "anonymous");
    }

    #[test]
    fn mtls_with_no_cert_rejects() {
        let groups = CompiledAuthGroups {
            read: CompiledAuth::None,
            write: CompiledAuth::Mtls,
        };
        let h = HeaderMap::new();
        let ctx = AuthContext {
            group: AuthGroup::Write,
            headers: &h,
            peer_cert: None,
        };
        let err = authorize(&groups, &ctx).unwrap_err();
        assert!(matches!(err, AuthFailure::NoClientCert));
    }
}
