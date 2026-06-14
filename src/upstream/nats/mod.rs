//! In-process NATS service-registration watcher (feature `nats`).
//!
//! Each NATS-backed pool watches its `reg.<…>` subtree (members self-register
//! there) plus the matching `override.<…>` subtree (operator drain/cordon
//! intent, operator-wins) and reconciles them into the pool's live member list,
//! reusing the same `write_lock` + `ArcSwap` swap, `build_member`, and
//! `drain_member` the admin API uses. Only `Nats`-sourced members are ever
//! touched; config/runtime members are left alone.
//!
//! Safety properties (see `docs/service-registration.md`):
//! - **Fail-static / freeze-on-disconnect:** a dropped watch never flushes
//!   membership; on reconnect the bucket is re-snapshotted (`keys()`), so
//!   expiries missed while disconnected are caught. NATS down at boot → the
//!   pool serves its static config and the watcher keeps retrying.
//! - **Allow-list + member caps:** every admission passes [`reconcile::admit`]
//!   before a member is built; rejections are counted and audited.

pub mod reconcile;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use async_nats::jetstream::kv::{Operation, Store};
use futures::StreamExt;

use crate::config::{NatsConfig, UpstreamMember, UpstreamNatsConfig};
use crate::shutdown::Coordinator;
use crate::upstream::drain::drain_member;
use crate::upstream::{MemberSource, Pool, Upstream, UpstreamPoolEntry, unix_now_ms};
use reconcile::Registration;

/// The watcher's running view of one pool's subtrees, threaded through the
/// snapshot → event → reconcile path so they share one piece of state rather
/// than passing three maps around (and re-created on each reconnect for a full
/// re-snapshot).
#[derive(Default)]
struct WatchState {
    /// `reg.*` key → parsed registration (the desired members).
    desired: HashMap<String, Registration>,
    /// Identity suffixes with a live `override.*` - the operator-wins suppress set.
    held: HashSet<String>,
    /// `reg.*` keys currently failing admission, so we audit only the transition
    /// into rejection rather than every reconcile.
    rejected: HashSet<String>,
}

/// Run the NATS watcher until drain begins. Spawned once at startup when a
/// `[nats]` block is present; returns immediately (a no-op) if no pool is
/// NATS-backed.
pub async fn run_watcher(pool: Arc<Pool>, nats: NatsConfig, shutdown: Coordinator) {
    let snap = pool.snapshot();
    let nats_pools: Vec<Arc<UpstreamPoolEntry>> = snap
        .values()
        .filter(|e| e.nats_cfg.is_some())
        .cloned()
        .collect();
    if nats_pools.is_empty() {
        return;
    }

    // Connect with retry - never blocks boot (this runs in a spawned task) and
    // never gives up until drain. The pools serve their static config until the
    // first successful snapshot.
    let client = tokio::select! {
        _ = shutdown.wait_for_drain_start() => return,
        c = connect_with_retry(&nats, &shutdown) => match c {
            Some(c) => c,
            None => return, // drain fired during retry
        },
    };
    let js = async_nats::jetstream::new(client);
    tracing::info!(url = %nats.url, bucket = %nats.bucket, pools = nats_pools.len(), "NATS watcher started");

    // One independent watch loop per pool, sharing the connection.
    let loops = nats_pools.into_iter().map(|entry| {
        let js = js.clone();
        let nats = nats.clone();
        let shutdown = shutdown.clone();
        async move { pool_loop(entry, js, nats, shutdown).await }
    });
    futures::future::join_all(loops).await;
}

async fn connect(nats: &NatsConfig) -> anyhow::Result<async_nats::Client> {
    let mut opts = async_nats::ConnectOptions::new().event_callback(|event| async move {
        match event {
            async_nats::Event::Connected => {
                metrics::gauge!("quik_nats_connected").set(1.0);
            }
            async_nats::Event::Disconnected => {
                metrics::gauge!("quik_nats_connected").set(0.0);
            }
            _ => {}
        }
    });
    if let Some(creds) = &nats.creds_file {
        // SECURITY (auth): the NATS credential is a file (never inline). The JWT
        // in a .creds is presented to the server on connect; over a plaintext
        // link it can be sniffed. Warn loudly rather than silently ship
        // credentials in the clear - production must use tls://.
        if !nats
            .url
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("tls://")
        {
            tracing::warn!(
                url = %nats.url,
                "NATS credentials are configured over a non-TLS URL - the credential JWT is sent \
                 in the clear; use tls:// in production"
            );
        }
        opts = opts
            .credentials_file(creds)
            .await
            .with_context(|| format!("reading NATS creds {}", creds.display()))?;
    }
    opts.connect(&nats.url)
        .await
        .with_context(|| format!("connecting to NATS {}", nats.url))
}

async fn connect_with_retry(
    nats: &NatsConfig,
    shutdown: &Coordinator,
) -> Option<async_nats::Client> {
    loop {
        match connect(nats).await {
            Ok(c) => return Some(c),
            Err(e) => {
                metrics::gauge!("quik_nats_connected").set(0.0);
                tracing::warn!(error = %e, url = %nats.url, "NATS connect failed; retrying (serving static config)");
                tokio::select! {
                    _ = shutdown.wait_for_drain_start() => return None,
                    _ = tokio::time::sleep(Duration::from_secs(nats.reconnect_secs)) => {}
                }
            }
        }
    }
}

/// Per-pool reconnect + watch loop.
async fn pool_loop(
    entry: Arc<UpstreamPoolEntry>,
    js: async_nats::jetstream::Context,
    nats: NatsConfig,
    shutdown: Coordinator,
) {
    let cfg = entry.nats_cfg.clone().expect("nats pool has nats_cfg");
    let reg_sub = cfg.subject.clone();
    let reg_prefix = subject_prefix(&reg_sub);
    let override_sub = override_subject(&reg_sub);
    let override_prefix = override_sub.as_deref().map(subject_prefix);
    // Parse the (static) allow-list once per pool, not per registration event.
    let allow = reconcile::compile_allow(&cfg.allow_addresses);

    // HARDENING (member caps): with no caps, one compromised/buggy credential can register unbounded
    // members. Caps default off (a tight cap fails unsafe), so nudge the operator
    // to bound it - here or, better, with JetStream bucket limits (docs §10).
    if cfg.max_members.is_none() && cfg.max_instances_per_service.is_none() {
        tracing::warn!(
            pool = %entry.name,
            "NATS pool has no max_members / max_instances_per_service cap; registrations are \
             unbounded - set JetStream bucket limits and/or caps to bound a runaway writer"
        );
    }

    loop {
        let store = match js.get_key_value(&nats.bucket).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(pool = %entry.name, error = %e, "opening NATS bucket failed; freezing");
                if sleep_or_drain(&nats, &shutdown).await {
                    return;
                }
                continue;
            }
        };

        // Authoritative snapshot (handles the empty-bucket case that `watch`'s
        // seen_current marker does not), then a full reconcile.
        let mut state = WatchState::default();
        if let Err(e) = snapshot(&store, &reg_prefix, override_prefix.as_deref(), &mut state).await
        {
            tracing::warn!(pool = %entry.name, error = %e, "NATS snapshot failed; freezing");
            if sleep_or_drain(&nats, &shutdown).await {
                return;
            }
            continue;
        }
        reconcile_full(&entry, &cfg, &allow, &mut state).await;

        // Live deltas over both subtrees.
        let subjects: Vec<String> = std::iter::once(reg_sub.clone())
            .chain(override_sub.clone())
            .collect();
        let mut watch = match store.watch_many(subjects).await {
            Ok(w) => w,
            Err(e) => {
                tracing::warn!(pool = %entry.name, error = %e, "NATS watch failed; freezing");
                if sleep_or_drain(&nats, &shutdown).await {
                    return;
                }
                continue;
            }
        };

        loop {
            tokio::select! {
                _ = shutdown.wait_for_drain_start() => return,
                item = watch.next() => match item {
                    Some(Ok(kv)) => {
                        apply_event(
                            &entry, &cfg, &allow, &reg_prefix, override_prefix.as_deref(),
                            &mut state, kv,
                        ).await;
                    }
                    Some(Err(e)) => {
                        // FREEZE: keep membership as-is; do not flush on a blip.
                        tracing::warn!(pool = %entry.name, error = %e, "NATS watch error; freezing membership");
                        break;
                    }
                    None => {
                        tracing::warn!(pool = %entry.name, "NATS watch stream ended; freezing membership");
                        break;
                    }
                }
            }
        }

        // Reconnect after a pause; the next snapshot reconciles forward and
        // catches anything that changed (incl. expiries) while disconnected.
        if sleep_or_drain(&nats, &shutdown).await {
            return;
        }
    }
}

/// Sleep `reconnect_secs`, returning `true` if drain fired (caller should exit).
async fn sleep_or_drain(nats: &NatsConfig, shutdown: &Coordinator) -> bool {
    tokio::select! {
        _ = shutdown.wait_for_drain_start() => true,
        _ = tokio::time::sleep(Duration::from_secs(nats.reconnect_secs)) => false,
    }
}

/// Read every current key in the pool's subtrees into `desired` (reg) / `held`
/// (override identity suffixes). `keys()` returns only present keys, so deleted/
/// expired entries are naturally absent.
async fn snapshot(
    store: &Store,
    reg_prefix: &str,
    override_prefix: Option<&str>,
    state: &mut WatchState,
) -> anyhow::Result<()> {
    let mut keys = store.keys().await.context("listing KV keys")?;
    while let Some(key) = keys.next().await {
        let key = key.context("reading KV key")?;
        if key_in_subtree(&key, reg_prefix) {
            if let Some(entry) = store.entry(&key).await.context("reading KV entry")?
                && entry.operation == Operation::Put
                && let Ok(reg) = reconcile::parse(&entry.value)
            {
                state.desired.insert(key, reg);
            }
        } else if let Some(op) = override_prefix
            && key_in_subtree(&key, op)
            && let Some(entry) = store.entry(&key).await.context("reading KV entry")?
            && entry.operation == Operation::Put
        {
            state
                .held
                .insert(reconcile::identity_suffix(&key).to_string());
        }
    }
    Ok(())
}

/// Apply one live watch event, then re-run the full (idempotent) reconcile.
async fn apply_event(
    entry: &Arc<UpstreamPoolEntry>,
    cfg: &UpstreamNatsConfig,
    allow: &[reconcile::AllowEntry],
    reg_prefix: &str,
    override_prefix: Option<&str>,
    state: &mut WatchState,
    kv: async_nats::jetstream::kv::Entry,
) {
    let op = match kv.operation {
        Operation::Put => "put",
        Operation::Delete => "delete",
        Operation::Purge => "purge",
    };
    metrics::counter!("quik_nats_watch_events_total", "op" => op).increment(1);

    if key_in_subtree(&kv.key, reg_prefix) {
        match kv.operation {
            Operation::Put => match reconcile::parse(&kv.value) {
                Ok(reg) => {
                    state.desired.insert(kv.key.clone(), reg);
                }
                Err(e) => {
                    tracing::warn!(pool = %entry.name, key = %kv.key, error = %e, "ignoring unparseable registration");
                    return;
                }
            },
            Operation::Delete | Operation::Purge => {
                state.desired.remove(&kv.key);
                state.rejected.remove(&kv.key);
            }
        }
    } else if let Some(op) = override_prefix
        && key_in_subtree(&kv.key, op)
    {
        let suffix = reconcile::identity_suffix(&kv.key).to_string();
        match kv.operation {
            Operation::Put => {
                state.held.insert(suffix);
            }
            Operation::Delete | Operation::Purge => {
                state.held.remove(&suffix);
            }
        }
    } else {
        return; // not our subtree
    }

    reconcile_full(entry, cfg, allow, state).await;
}

/// Converge the pool's `Nats`-sourced members to the admitted subset of
/// `desired` (minus `held`). Idempotent.
async fn reconcile_full(
    entry: &Arc<UpstreamPoolEntry>,
    cfg: &UpstreamNatsConfig,
    allow: &[reconcile::AllowEntry],
    state: &mut WatchState,
) {
    let WatchState {
        desired,
        held,
        rejected,
    } = state;
    // SECURITY: this loop is the trust boundary for self-registration. Every
    // `desired` entry is a self-asserted value an untrusted writer put in the
    // bucket - its `address` is attacker-controlled. Nothing reaches the live
    // member list (and thus receives proxied traffic + injected identity headers)
    // without passing `reconcile::admit` (allow-list + member caps) here first.
    // Deterministic key order keeps cap accounting stable.
    let mut accepted: HashSet<String> = HashSet::new();
    let mut keys: Vec<&String> = desired.keys().collect();
    keys.sort();
    for k in keys {
        let reg = &desired[k];
        // SECURITY (operator-wins): a live override.* suppresses this member and
        // it can't be resurrected by a re-registration. A service credential
        // cannot write override.* (NATS subject permissions enforce the
        // reg.*/override.* split), so this precedence is structural, not advisory.
        if held.contains(reconcile::identity_suffix(k)) {
            continue;
        }
        match reconcile::admit(
            k,
            &reg.address,
            &accepted,
            allow,
            cfg.max_members,
            cfg.max_instances_per_service,
        ) {
            Ok(()) => {
                rejected.remove(k);
                accepted.insert(k.clone());
            }
            Err(rej) => {
                metrics::counter!(
                    "quik_nats_registration_rejected_total",
                    "pool" => entry.name.clone(),
                    "reason" => rej.as_str(),
                )
                .increment(1);
                // Audit + warn only on the transition into rejection, so a
                // persistently-bad key doesn't spam every reconcile.
                if rejected.insert(k.clone()) {
                    tracing::warn!(
                        target: "quik::admin::audit",
                        event = "nats_reconcile",
                        action = "register_rejected",
                        pool = %entry.name,
                        member = %reg.address,
                        result = rej.as_str(),
                        "NATS registration rejected"
                    );
                }
            }
        }
    }

    // The accepted addresses (with scheme), derived from the accepted keys.
    let accepted_addrs: HashMap<&str, &Registration> = accepted
        .iter()
        .map(|k| {
            let reg = &desired[k];
            (reg.address.as_str(), reg)
        })
        .collect();

    let now_ms = unix_now_ms();
    let mut to_drain: Vec<Arc<Upstream>> = Vec::new();
    let mut to_add: Vec<UpstreamMember> = Vec::new();

    {
        let _w = entry.write_lock.lock().await;
        let current = entry.members.load_full();
        let mut present: HashSet<String> = HashSet::new();
        let mut next: Vec<Arc<Upstream>> = Vec::with_capacity(current.len());

        for m in current.iter() {
            if m.source != MemberSource::Nats {
                next.push(m.clone()); // never touch config/runtime members
                continue;
            }
            present.insert(m.address.clone());
            next.push(m.clone());
            if !accepted_addrs.contains_key(m.address.as_str()) && m.lifecycle.is_active() {
                // No longer desired (deleted / expired / held / rejected) →
                // begin a graceful drain; the drain task removes it when
                // in-flight reaches zero (near-instant for a dead backend).
                if m.lifecycle.begin_drain(now_ms).is_ok() {
                    to_drain.push(m.clone());
                }
            }
        }

        for (addr, reg) in &accepted_addrs {
            if !present.contains(*addr) {
                to_add.push(UpstreamMember {
                    address: addr.to_string(),
                    scheme: reg.scheme.clone(),
                });
            }
        }

        // Build + append new members under the same lock for a single swap.
        for mc in &to_add {
            match entry.build_member(mc) {
                Ok(mut m) => {
                    m.source = MemberSource::Nats;
                    next.push(Arc::new(m));
                    metrics::counter!(
                        "quik_nats_reconcile_total",
                        "pool" => entry.name.clone(),
                        "action" => "add",
                    )
                    .increment(1);
                    tracing::info!(
                        target: "quik::admin::audit",
                        event = "nats_reconcile",
                        action = "member_added",
                        pool = %entry.name,
                        member = %mc.address,
                        result = "ok",
                        "NATS member added"
                    );
                }
                Err(e) => {
                    tracing::warn!(pool = %entry.name, address = %mc.address, error = %e, "invalid NATS member, skipping");
                }
            }
        }

        entry.members.store(Arc::new(next));
    }

    // Spawn drains outside the write lock.
    let drain_timeout = Duration::from_millis(entry.drain_cfg.timeout_ms);
    for m in to_drain {
        let entry = entry.clone();
        metrics::counter!(
            "quik_nats_reconcile_total",
            "pool" => entry.name.clone(),
            "action" => "remove",
        )
        .increment(1);
        tracing::info!(
            target: "quik::admin::audit",
            event = "nats_reconcile",
            action = "member_removed",
            pool = %entry.name,
            member = %m.address,
            result = "ok",
            "NATS member removed (draining)"
        );
        tokio::spawn(async move {
            drain_member(m, entry, drain_timeout, true).await;
        });
    }
}

/// Strip a trailing wildcard token (`.>` / `.*`) to get the literal key prefix.
fn subject_prefix(subject: &str) -> String {
    subject
        .trim_end_matches(['>', '*'])
        .trim_end_matches('.')
        .to_string()
}

/// The operator-override subtree for a `reg.*` subject: first token → `override`.
/// `reg.shop.checkout.>` → `override.shop.checkout.>`.
fn override_subject(reg_subject: &str) -> Option<String> {
    reg_subject
        .split_once('.')
        .map(|(_, rest)| format!("override.{rest}"))
}

/// True if `key` falls under the literal `prefix` subtree (respecting token
/// boundaries - `reg.shop.checkout` does not match `reg.shop.checkoutX.c1`).
fn key_in_subtree(key: &str, prefix: &str) -> bool {
    key.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_helpers() {
        assert_eq!(subject_prefix("reg.shop.checkout.>"), "reg.shop.checkout");
        assert_eq!(subject_prefix("reg.shop.*"), "reg.shop");
        assert_eq!(
            override_subject("reg.shop.checkout.>").as_deref(),
            Some("override.shop.checkout.>")
        );
        assert!(key_in_subtree("reg.shop.checkout.c1", "reg.shop.checkout"));
        assert!(!key_in_subtree("reg.shop.cart.c1", "reg.shop.checkout"));
        // Prefix must respect token boundaries.
        assert!(!key_in_subtree(
            "reg.shop.checkoutX.c1",
            "reg.shop.checkout"
        ));
    }
}
