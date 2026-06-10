//! Service health checks — an http(s) GET (expect 2xx) or a bare TCP connect,
//! each bounded by a timeout.

use std::time::Duration;

use anyhow::{Context, Result};

use crate::config::{HealthConfig, Protocol};

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
    pub fn new(cfg: &HealthConfig, address: &str) -> Result<Self> {
        let timeout = Duration::from_millis(cfg.timeout_ms);
        let scheme = match cfg.protocol {
            Protocol::Http => "http",
            Protocol::Https => "https",
            Protocol::Tcp => "tcp",
        };
        let method = cfg
            .method
            .parse::<reqwest::Method>()
            .with_context(|| format!("invalid [health].method '{}'", cfg.method))?;
        let client = reqwest::Client::builder()
            .timeout(timeout)
            // Health checks to internal backends with self-signed certs are
            // common; this is a liveness probe, not a security boundary.
            .danger_accept_invalid_certs(true)
            .build()
            .context("building health-check HTTP client")?;
        Ok(Self {
            protocol: cfg.protocol,
            address: address.to_string(),
            url: format!("{scheme}://{address}{}", cfg.endpoint),
            method,
            timeout,
            client,
        })
    }

    /// True if the service is currently healthy.
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
