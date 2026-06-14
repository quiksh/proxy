//! Liveness probes for the registered instance - an http(s) GET (expect 2xx) or
//! a bare TCP connect, each bounded by a timeout. Used to gate the heartbeat
//! (does this instance still belong in the registry?), which is a different
//! question from quik's own routing health check.

use std::time::Duration;

use anyhow::{Context, Result};

use crate::config::{LivenessConfig, Protocol};

pub struct HealthChecker {
    protocol: Protocol,
    /// `host:port` for the TCP connect.
    address: String,
    /// Full URL for http(s) checks.
    url: String,
    method: reqwest::Method,
    timeout: Duration,
    client: reqwest::Client,
}

impl HealthChecker {
    pub fn new(cfg: &LivenessConfig, address: &str) -> Result<Self> {
        let timeout = Duration::from_millis(cfg.timeout_ms);
        let scheme = match cfg.protocol {
            Protocol::Http => "http",
            Protocol::Https => "https",
            Protocol::Tcp => "tcp",
        };
        let method = cfg
            .method
            .parse::<reqwest::Method>()
            .with_context(|| format!("invalid [liveness].method '{}'", cfg.method))?;
        let redirect = if cfg.max_redirects == 0 {
            reqwest::redirect::Policy::none()
        } else {
            reqwest::redirect::Policy::limited(cfg.max_redirects)
        };
        let client = reqwest::Client::builder()
            .timeout(timeout)
            // Verify certs by default; opt out for trusted self-signed backends.
            .danger_accept_invalid_certs(!cfg.tls_verify)
            // A liveness probe should hit the instance directly; don't let it be
            // bounced elsewhere unless the operator opts into redirects.
            .redirect(redirect)
            .build()
            .context("building liveness-probe HTTP client")?;
        Ok(Self {
            protocol: cfg.protocol,
            address: address.to_string(),
            url: format!("{scheme}://{address}{}", cfg.endpoint),
            method,
            timeout,
            client,
        })
    }

    /// True if the instance currently answers the liveness probe.
    pub async fn probe(&self) -> bool {
        match self.protocol {
            Protocol::Tcp => matches!(
                tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(&self.address))
                    .await,
                Ok(Ok(_))
            ),
            Protocol::Http | Protocol::Https => {
                match self
                    .client
                    .request(self.method.clone(), &self.url)
                    .send()
                    .await
                {
                    Ok(resp) => resp.status().is_success(),
                    Err(_) => false,
                }
            }
        }
    }
}
