//! quik-register — a service-registration sidecar for quik.
//!
//! Health-checks a local service and registers it into a NATS JetStream KV
//! bucket while healthy (heartbeating the lease), deregistering it when it
//! fails or on shutdown. quik's NATS watcher reconciles the bucket into its
//! pool. See `docs/service-registration.md`.
//!
//!   quik-register --config /etc/quik-register/quik-register.toml

mod agent;
mod config;
mod health;

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

fn parse_config_path() -> Result<PathBuf> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--config") | Some("-c") => args
            .next()
            .map(PathBuf::from)
            .context("--config requires a path argument"),
        Some("--help") | Some("-h") => {
            eprintln!("usage: quik-register --config <path>");
            std::process::exit(0);
        }
        Some(other) if !other.starts_with('-') => Ok(PathBuf::from(other)),
        Some(other) => bail!("unknown argument: {other}"),
        None => bail!("missing --config <path>"),
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let path = parse_config_path()?;
    let cfg = config::load(&path)?;
    init_tracing();
    agent::run(cfg).await
}
