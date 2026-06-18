use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use quik::{admin, auth, config, egress, observability, proxy, routing, shutdown, tls, upstream};
use tokio::net::TcpListener;

fn parse_config_path() -> Result<PathBuf> {
    let mut args = std::env::args().skip(1);
    let Some(first) = args.next() else {
        anyhow::bail!("missing --config <path>");
    };
    match first.as_str() {
        "--config" | "-c" => args
            .next()
            .map(PathBuf::from)
            .context("--config requires a path argument"),
        "--help" | "-h" => {
            eprintln!("usage: quik --config <path>");
            std::process::exit(0);
        }
        other if !other.starts_with('-') => Ok(PathBuf::from(other)),
        other => anyhow::bail!("unknown argument: {other}"),
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let config_path = parse_config_path()?;
    let cfg = config::load(&config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;
    let cfg = Arc::new(cfg);

    observability::init_tracing(&cfg.logging)?;
    let metrics = observability::init_metrics()?;

    tracing::info!(
        config = %config_path.display(),
        mode = ?cfg.mode,
        listen = %cfg.listener.bind,
        admin = %cfg.admin.bind,
        "quik starting"
    );

    let shutdown = shutdown::Coordinator::new(
        cfg.shutdown.drain_grace_seconds,
        cfg.shutdown.pre_drain_grace_seconds,
    );
    shutdown.install_signal_handlers();

    let routing = Arc::new(routing::SharedRoutingTable::from_config(&cfg)?);
    let upstreams = Arc::new(upstream::Pool::from_config(&cfg)?);
    let auth_registry = Arc::new(auth::AuthRegistry::from_config(&cfg)?);

    // Background sampler keeps the `quik_upstream_inflight` gauge fresh
    // without paying a metrics emission cost on every request.
    tokio::spawn(observability::inflight_sampler(
        upstreams.clone(),
        std::time::Duration::from_secs(5),
        shutdown.clone(),
    ));

    // NATS service-registration watcher (feature `nats`). Spawned only when a
    // `[nats]` block is present; pools serve their static config until it
    // connects, and keep last-known membership if it drops.
    #[cfg(feature = "nats")]
    if let Some(nats_cfg) = cfg.nats.clone() {
        tokio::spawn(upstream::nats::run_watcher(
            upstreams.clone(),
            nats_cfg,
            shutdown.clone(),
        ));
    }

    // One active-health probe task per pool that opted in. Pools without
    // `[upstreams.active_health].enabled = true` get nothing spawned and
    // remain on passive health only.
    for entry in upstreams.snapshot().values() {
        if entry.active_health_cfg.enabled {
            tokio::spawn(upstream::probe::run_pool_probes(
                entry.clone(),
                shutdown.clone(),
            ));
        }
    }

    let admin_listener = TcpListener::bind(cfg.admin.bind)
        .await
        .with_context(|| format!("binding admin {}", cfg.admin.bind))?;
    let proxy_listener = TcpListener::bind(cfg.listener.bind)
        .await
        .with_context(|| format!("binding listener {}", cfg.listener.bind))?;

    // Resolve admin auth - env-var-backed tokens fail fast on missing vars.
    let admin_auth =
        admin::compile_auth(&cfg.admin).context("compiling admin auth (check token env vars)")?;
    let admin_state = admin::AdminState {
        metrics,
        upstreams: upstreams.clone(),
        auth_groups: admin_auth,
    };
    let admin_tls_cfg = cfg.admin.tls.clone();
    let shutdown_for_admin = shutdown.clone();
    let admin_task = tokio::spawn(async move {
        admin::serve(
            admin_listener,
            admin_state,
            admin_tls_cfg.as_ref(),
            shutdown_for_admin,
        )
        .await
    });

    let tls_acceptor = tls::build_acceptor(&cfg.listener.tls).context("building TLS acceptor")?;
    let proxy_task = tokio::spawn(proxy::serve(
        proxy_listener,
        tls_acceptor,
        proxy::ServerState {
            routing,
            upstreams,
            auth: auth_registry.clone(),
            mode: cfg.mode,
            forwarded: Arc::new(quik::headers::ForwardedPolicy::from_config(&cfg.forwarded)),
            access: Arc::new(proxy::AccessLogFields::from_logging(&cfg.logging)?),
            limits: Arc::new(cfg.listener.limits.clone()),
        },
        shutdown.clone(),
    ));

    // Optional egress (forward) proxy. Only spawned when `[egress]` is in
    // config - quik runs purely as a reverse proxy if the block is absent.
    let egress_task = if let Some(egress_cfg) = &cfg.egress {
        let policy = Arc::new(egress::EgressPolicy::from_config_with_auth(
            egress_cfg,
            &auth_registry,
        )?);
        let listener = TcpListener::bind(egress_cfg.bind)
            .await
            .with_context(|| format!("binding egress {}", egress_cfg.bind))?;
        tracing::info!(
            addr = %egress_cfg.bind,
            default = ?egress_cfg.default_action,
            rules = egress_cfg.rules.len(),
            sni_enforce = egress_cfg.sni_enforce,
            "egress listener bound"
        );
        Some(tokio::spawn(egress::serve(
            listener,
            policy,
            shutdown.clone(),
        )))
    } else {
        None
    };

    match shutdown.wait_for_exit().await {
        shutdown::ExitReason::DrainComplete => {
            tracing::info!("drain grace elapsed, exiting cleanly");
            let _ = proxy_task.await;
            let _ = admin_task.await;
            if let Some(t) = egress_task {
                let _ = t.await;
            }
        }
        shutdown::ExitReason::Forced => {
            tracing::warn!("force exit - skipping drain grace, in-flight requests will be aborted");
            proxy_task.abort();
            admin_task.abort();
            if let Some(t) = egress_task {
                t.abort();
            }
        }
    }

    Ok(())
}
