//! NATS service-registration e2e (feature `nats`).
//!
//! Drives a real JetStream KV bucket and asserts quik reconciles it into pool
//! membership, enforces the H1 allow-list, honours operator overrides, and
//! removes members on delete. Run with:
//!
//!   docker run -d --name nats -p 4222:4222 nats:2.11 -js
//!   cargo test --features nats --test e2e_nats
//!
//! Self-skips (does not fail) when no NATS is reachable, so a default
//! `cargo test` — where this whole file is compiled out — and a feature build
//! without a server both stay green. Point at a non-default server with
//! QUIK_TEST_NATS_URL.
#![cfg(feature = "nats")]

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use common::{Backend, Backends, ProxySpec, https_client, route, spawn_proxy_with_nats};
use quik::async_nats;
use quik::config::{NatsConfig, UpstreamNatsConfig};

fn nats_url() -> String {
    std::env::var("QUIK_TEST_NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string())
}

/// Connect to NATS, or return `None` so the test self-skips when no server is
/// reachable (keeps CI green without NATS).
async fn nats_or_skip(test: &str) -> Option<async_nats::Client> {
    match tokio::time::timeout(Duration::from_secs(2), async_nats::connect(nats_url())).await {
        Ok(Ok(c)) => Some(c),
        _ => {
            eprintln!(
                "[skip] {test}: no NATS at {} (set QUIK_TEST_NATS_URL)",
                nats_url()
            );
            None
        }
    }
}

/// Drop and recreate a KV bucket so each test starts clean.
async fn fresh_bucket(
    client: &async_nats::Client,
    bucket: &str,
) -> async_nats::jetstream::kv::Store {
    let js = async_nats::jetstream::new(client.clone());
    let _ = js.delete_key_value(bucket).await;
    js.create_key_value(async_nats::jetstream::kv::Config {
        bucket: bucket.to_string(),
        history: 1,
        ..Default::default()
    })
    .await
    .expect("create bucket")
}

fn proxy_url(addr: SocketAddr, path: &str) -> String {
    format!("https://localhost:{}{}", addr.port(), path)
}

async fn member_addrs(admin: SocketAddr, pool: &str) -> Vec<String> {
    let client = reqwest::Client::new();
    let Ok(resp) = client
        .get(format!("http://{admin}/admin/pools/{pool}"))
        .send()
        .await
    else {
        return vec![];
    };
    if resp.status() != reqwest::StatusCode::OK {
        return vec![];
    }
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    body["members"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|m| m["address"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Poll the admin API until `pred` holds over the pool's member addresses, or a
/// deadline passes. Returns whether the predicate held.
async fn wait_until<F: Fn(&[String]) -> bool>(admin: SocketAddr, pool: &str, pred: F) -> bool {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let addrs = member_addrs(admin, pool).await;
        if pred(&addrs) {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn metrics_text(admin: SocketAddr) -> String {
    reqwest::Client::new()
        .get(format!("http://{admin}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap()
}

fn pool_with(subject: &str, allow: &[&str]) -> Backends {
    Backends::http("p", vec![]).with_nats(UpstreamNatsConfig {
        subject: subject.to_string(),
        allow_addresses: allow.iter().map(|s| s.to_string()).collect(),
        max_members: None,
        max_instances_per_service: None,
    })
}

fn nats_cfg(bucket: &str) -> NatsConfig {
    NatsConfig {
        url: nats_url(),
        bucket: bucket.to_string(),
        creds_file: None,
        reconnect_secs: 1,
    }
}

fn reg_value(addr: SocketAddr) -> Vec<u8> {
    json!({ "address": addr.to_string(), "scheme": "http" })
        .to_string()
        .into_bytes()
}

#[tokio::test]
async fn register_adds_member_and_routes() {
    let Some(client) = nats_or_skip("register_adds_member_and_routes").await else {
        return;
    };
    let bucket = "quik_e2e_register";
    let store = fresh_bucket(&client, bucket).await;
    let backend = Backend::spawn("a").await;

    // Pre-seed one registration (caught by the watcher's initial snapshot),
    // then spawn quik. 127.0.0.0/8 admits the loopback backend.
    store
        .put("reg.t.svc.i1", reg_value(backend.addr).into())
        .await
        .unwrap();

    let proxy = spawn_proxy_with_nats(
        ProxySpec {
            pools: vec![pool_with("reg.t.svc.>", &["127.0.0.0/8"])],
            routes: vec![route("/", "p")],
        },
        nats_cfg(bucket),
    )
    .await;

    assert!(
        wait_until(proxy.admin_addr, "p", |a| a
            .contains(&backend.addr.to_string()))
        .await,
        "registered member should appear in the pool"
    );

    // Routes traffic to the registered backend.
    let r = https_client()
        .get(proxy_url(proxy.addr, "/hello"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    assert!(!backend.calls().is_empty());

    // A live Put (after the watch is established) is also picked up.
    let b2 = Backend::spawn("b").await;
    store
        .put("reg.t.svc.i2", reg_value(b2.addr).into())
        .await
        .unwrap();
    assert!(
        wait_until(proxy.admin_addr, "p", |a| a.len() == 2
            && a.contains(&b2.addr.to_string()))
        .await,
        "live registration should be reconciled in"
    );
}

#[tokio::test]
async fn disallowed_address_is_rejected() {
    let Some(client) = nats_or_skip("disallowed_address_is_rejected").await else {
        return;
    };
    let bucket = "quik_e2e_reject";
    let store = fresh_bucket(&client, bucket).await;
    let backend = Backend::spawn("a").await; // loopback 127.x

    // allow-list is 10.0.0.0/8 — the loopback backend is NOT in it (H1).
    store
        .put("reg.t.svc.i1", reg_value(backend.addr).into())
        .await
        .unwrap();

    let proxy = spawn_proxy_with_nats(
        ProxySpec {
            pools: vec![pool_with("reg.t.svc.>", &["10.0.0.0/8"])],
            routes: vec![route("/", "p")],
        },
        nats_cfg(bucket),
    )
    .await;

    // Give the watcher time to snapshot + reject, then assert it never joined.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        member_addrs(proxy.admin_addr, "p").await.is_empty(),
        "a disallowed address must never be admitted"
    );
    let metrics = metrics_text(proxy.admin_addr).await;
    assert!(
        metrics
            .lines()
            .any(|l| l.starts_with("quik_nats_registration_rejected_total")
                && l.contains("reason=\"address_not_allowed\"")),
        "rejection must be counted; metrics:\n{metrics}"
    );
}

#[tokio::test]
async fn delete_removes_member() {
    let Some(client) = nats_or_skip("delete_removes_member").await else {
        return;
    };
    let bucket = "quik_e2e_delete";
    let store = fresh_bucket(&client, bucket).await;
    let backend = Backend::spawn("a").await;
    store
        .put("reg.t.svc.i1", reg_value(backend.addr).into())
        .await
        .unwrap();

    let proxy = spawn_proxy_with_nats(
        ProxySpec {
            pools: vec![pool_with("reg.t.svc.>", &["127.0.0.0/8"]).with_drain_timeout_ms(1000)],
            routes: vec![route("/", "p")],
        },
        nats_cfg(bucket),
    )
    .await;
    assert!(wait_until(proxy.admin_addr, "p", |a| a.len() == 1).await);

    // Explicit delete → the member drains and is removed.
    store.delete("reg.t.svc.i1").await.unwrap();
    assert!(
        wait_until(proxy.admin_addr, "p", |a| a.is_empty()).await,
        "deleted registration should be removed from the pool"
    );
}

#[tokio::test]
async fn override_suppresses_then_restores() {
    let Some(client) = nats_or_skip("override_suppresses_then_restores").await else {
        return;
    };
    let bucket = "quik_e2e_override";
    let store = fresh_bucket(&client, bucket).await;
    let backend = Backend::spawn("a").await;
    store
        .put("reg.t.svc.i1", reg_value(backend.addr).into())
        .await
        .unwrap();

    let proxy = spawn_proxy_with_nats(
        ProxySpec {
            pools: vec![pool_with("reg.t.svc.>", &["127.0.0.0/8"]).with_drain_timeout_ms(1000)],
            routes: vec![route("/", "p")],
        },
        nats_cfg(bucket),
    )
    .await;
    assert!(wait_until(proxy.admin_addr, "p", |a| a.len() == 1).await);

    // Operator override (same identity suffix) → member is drained/suppressed,
    // even though the reg key still says "present" (resurrection guard).
    store
        .put(
            "override.t.svc.i1",
            b"{\"action\":\"drain\"}".to_vec().into(),
        )
        .await
        .unwrap();
    assert!(
        wait_until(proxy.admin_addr, "p", |a| a.is_empty()).await,
        "operator override should suppress the member"
    );

    // Remove the override → the still-present reg key is admitted again.
    store.delete("override.t.svc.i1").await.unwrap();
    assert!(
        wait_until(proxy.admin_addr, "p", |a| a.len() == 1).await,
        "removing the override should restore the member"
    );
}
