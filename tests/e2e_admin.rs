//! Admin API e2e — live registration + auth.
//!
//! Drives the admin listener over plain HTTP (the default; mTLS variant is
//! covered at the unit level in src/admin/auth.rs and via TLS-handshake
//! tests below).
#![allow(unsafe_code)] // env::set_var is `unsafe` in edition 2024; tests need it.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use http::StatusCode;
use serde_json::Value;

use common::{
    Backend, Backends, ProxySpec, https_client, route, spawn_proxy, spawn_proxy_with_admin_auth,
};

fn proxy_url(addr: SocketAddr, path: &str) -> String {
    format!("https://localhost:{}{}", addr.port(), path)
}

fn admin_url(addr: SocketAddr, path: &str) -> String {
    format!("http://{addr}{path}")
}

async fn one_pool_one_route() -> (Backend, common::ProxyHandle) {
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![Backends::http("pool-a", vec![backend.addr])],
        routes: vec![route("/", "pool-a")],
    })
    .await;
    (backend, proxy)
}

// ── GET endpoints ───────────────────────────────────────────────────────────

#[tokio::test]
async fn lists_pools_with_members_from_config() {
    let (backend, proxy) = one_pool_one_route().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(admin_url(proxy.admin_addr, "/admin/pools"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    let pools = body["pools"].as_array().unwrap();
    assert_eq!(pools.len(), 1);
    let pool = &pools[0];
    assert_eq!(pool["name"], "pool-a");
    let members = pool["members"].as_array().unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0]["address"], backend.addr.to_string());
    assert_eq!(members[0]["lifecycle"], "active");
    assert_eq!(members[0]["routable"], true);
}

#[tokio::test]
async fn get_pool_returns_404_for_unknown() {
    let (_backend, proxy) = one_pool_one_route().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(admin_url(proxy.admin_addr, "/admin/pools/ghost"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body: Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("pool not found"));
}

#[tokio::test]
async fn get_member_returns_full_state_object() {
    let (backend, proxy) = one_pool_one_route().await;
    let id = backend.addr.to_string();
    let encoded = urlencode(&id);
    let url = admin_url(
        proxy.admin_addr,
        &format!("/admin/pools/pool-a/members/{encoded}"),
    );
    let client = reqwest::Client::new();
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["id"], id);
    assert_eq!(body["lifecycle"], "active");
    assert_eq!(body["routable"], true);
    assert!(body["passive"].is_object());
    assert!(body["active"].is_object());
    // active disabled by default → enabled=false, state=initial
    assert_eq!(body["active"]["enabled"], false);
}

// ── Add member ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn add_member_routes_traffic_to_new_backend() {
    let backend_a = Backend::spawn("a").await;
    let backend_b = Backend::spawn("b").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![Backends::http("pool-a", vec![backend_a.addr])],
        routes: vec![route("/", "pool-a")],
    })
    .await;

    // Add backend_b at runtime.
    let client = reqwest::Client::new();
    let resp = client
        .post(admin_url(proxy.admin_addr, "/admin/pools/pool-a/members"))
        .json(&serde_json::json!({
            "address": backend_b.addr.to_string(),
            "scheme": "http",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["address"], backend_b.addr.to_string());
    assert_eq!(body["lifecycle"], "active");

    // Drive traffic. Round-robin should hit both members.
    let proxy_client = https_client();
    for _ in 0..10 {
        let _ = proxy_client
            .get(proxy_url(proxy.addr, "/hello"))
            .send()
            .await
            .unwrap();
    }
    let calls_a = backend_a.calls().len();
    let calls_b = backend_b.calls().len();
    assert!(
        calls_a > 0 && calls_b > 0,
        "both backends should have received traffic: a={calls_a}, b={calls_b}"
    );
}

#[tokio::test]
async fn add_member_conflict_returns_409() {
    let (backend, proxy) = one_pool_one_route().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(admin_url(proxy.admin_addr, "/admin/pools/pool-a/members"))
        .json(&serde_json::json!({
            "address": backend.addr.to_string(),
            "scheme": "http",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn add_member_invalid_address_returns_400() {
    let (_backend, proxy) = one_pool_one_route().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(admin_url(proxy.admin_addr, "/admin/pools/pool-a/members"))
        .json(&serde_json::json!({
            "address": "not a valid address",
            "scheme": "http",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_member_to_unknown_pool_returns_404() {
    let (_backend, proxy) = one_pool_one_route().await;
    let backend_b = Backend::spawn("b").await;
    let client = reqwest::Client::new();
    let resp = client
        .post(admin_url(proxy.admin_addr, "/admin/pools/ghost/members"))
        .json(&serde_json::json!({
            "address": backend_b.addr.to_string(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── Drain / remove ──────────────────────────────────────────────────────────

#[tokio::test]
async fn delete_member_with_no_inflight_completes_quickly() {
    let backend_a = Backend::spawn("a").await;
    let backend_b = Backend::spawn("b").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![
            Backends::http("pool-a", vec![backend_a.addr, backend_b.addr])
                .with_drain_timeout_ms(2000),
        ],
        routes: vec![route("/", "pool-a")],
    })
    .await;
    let id = backend_b.addr.to_string();
    let encoded = urlencode(&id);

    let client = reqwest::Client::new();
    let resp = client
        .delete(admin_url(
            proxy.admin_addr,
            &format!("/admin/pools/pool-a/members/{encoded}"),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["lifecycle"], "draining");

    // Inflight is 0 → drain task should complete in under one tick (200ms)
    // plus the drain task's check interval. Give it 1s margin.
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    loop {
        if std::time::Instant::now() > deadline {
            panic!("member never removed");
        }
        let r = client
            .get(admin_url(
                proxy.admin_addr,
                &format!("/admin/pools/pool-a/members/{encoded}"),
            ))
            .send()
            .await
            .unwrap();
        if r.status() == StatusCode::NOT_FOUND {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn drain_member_without_removal_stops_new_traffic() {
    let backend_a = Backend::spawn("a").await;
    let backend_b = Backend::spawn("b").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![Backends::http(
            "pool-a",
            vec![backend_a.addr, backend_b.addr],
        )],
        routes: vec![route("/", "pool-a")],
    })
    .await;
    let id_b = backend_b.addr.to_string();
    let encoded = urlencode(&id_b);

    // POST /drain — member transitions to draining but isn't removed.
    let client = reqwest::Client::new();
    let resp = client
        .post(admin_url(
            proxy.admin_addr,
            &format!("/admin/pools/pool-a/members/{encoded}/drain"),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // Hammer the proxy — all traffic should now go to backend_a.
    let proxy_client = https_client();
    for _ in 0..20 {
        let _ = proxy_client
            .get(proxy_url(proxy.addr, "/hello"))
            .send()
            .await
            .unwrap();
    }
    // backend_b might have one race-window hit before its lifecycle was
    // observed by the pick path; accept up to 1.
    let calls_b = backend_b.calls().len();
    assert!(
        calls_b <= 1,
        "drained member should see ~0 traffic, got {calls_b}"
    );
    assert!(
        backend_a.calls().len() >= 19,
        "active member should absorb most traffic"
    );
}

#[tokio::test]
async fn undrain_restores_routing() {
    let backend_a = Backend::spawn("a").await;
    // b responds slowly so we can hold one request in-flight against it. The
    // drain task's first poll is immediate, so a member with zero in-flight is
    // marked `drained` almost at once — undrain would then race and lose. An
    // in-flight request keeps b `draining` deterministically until we undrain.
    let backend_b = Backend::spawn_with_delay("b", Duration::from_millis(500)).await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![Backends::http(
            "pool-a",
            vec![backend_a.addr, backend_b.addr],
        )],
        routes: vec![route("/", "pool-a")],
    })
    .await;
    let id_b = backend_b.addr.to_string();
    let encoded = urlencode(&id_b);

    let proxy_client = https_client();
    // Warm-up consumes round-robin index 0 (→ backend_a), so the next pick
    // lands deterministically on b.
    let _ = proxy_client
        .get(proxy_url(proxy.addr, "/warmup"))
        .send()
        .await
        .unwrap();
    // Pin one in-flight request onto b (index 1). Held open by b's delay.
    let pin = {
        let c = proxy_client.clone();
        let addr = proxy.addr;
        tokio::spawn(async move { c.get(proxy_url(addr, "/pin")).send().await })
    };
    // Let the proxy pick b and increment its inflight counter.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    // Drain b — it stays draining because the pinned request is in-flight.
    let drain_resp = client
        .post(admin_url(
            proxy.admin_addr,
            &format!("/admin/pools/pool-a/members/{encoded}/drain"),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(drain_resp.status(), StatusCode::ACCEPTED);
    // Undrain b — succeeds because it's still draining, not drained.
    let resp = client
        .post(admin_url(
            proxy.admin_addr,
            &format!("/admin/pools/pool-a/members/{encoded}/undrain"),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["lifecycle"], "active");

    let _ = pin.await;
    let b_before = backend_b.calls().len();

    // Backend_b should now receive traffic again. Issue the probe requests
    // concurrently so b's per-request delay doesn't serialise the check.
    let mut handles = Vec::new();
    for _ in 0..16 {
        let c = proxy_client.clone();
        let addr = proxy.addr;
        handles.push(tokio::spawn(async move {
            let _ = c.get(proxy_url(addr, "/hello")).send().await;
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    let calls_b = backend_b.calls().len() - b_before;
    assert!(
        calls_b >= 3,
        "undrained member should resume taking traffic (got {calls_b}/16)"
    );
}

#[tokio::test]
async fn delete_nonexistent_member_returns_404() {
    let (_backend, proxy) = one_pool_one_route().await;
    let client = reqwest::Client::new();
    let resp = client
        .delete(admin_url(
            proxy.admin_addr,
            "/admin/pools/pool-a/members/127.0.0.1%3A1",
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn undrain_active_member_returns_409() {
    let (backend, proxy) = one_pool_one_route().await;
    let encoded = urlencode(&backend.addr.to_string());
    let client = reqwest::Client::new();
    let resp = client
        .post(admin_url(
            proxy.admin_addr,
            &format!("/admin/pools/pool-a/members/{encoded}/undrain"),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

// ── Auth ────────────────────────────────────────────────────────────────────

const TEST_TOKEN_ENV: &str = "QUIK_E2E_ADMIN_TOKEN";
const TEST_TOKEN: &str = "supersecret-test-token-9c0f";

#[tokio::test]
async fn bearer_auth_rejects_missing_token() {
    // SAFETY: setting env vars from concurrent tests is non-thread-safe in std.
    // Each test uses a unique env var name to avoid collisions.
    unsafe {
        std::env::set_var(TEST_TOKEN_ENV, TEST_TOKEN);
    }
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy_with_admin_auth(
        ProxySpec {
            pools: vec![Backends::http("pool-a", vec![backend.addr])],
            routes: vec![route("/", "pool-a")],
        },
        quik::config::AdminAuthGroups {
            read: quik::config::AdminAuthConfig::None,
            write: quik::config::AdminAuthConfig::BearerToken {
                token_env: TEST_TOKEN_ENV.to_string(),
            },
        },
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(admin_url(proxy.admin_addr, "/admin/pools/pool-a/members"))
        .json(&serde_json::json!({"address": "127.0.0.1:1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    unsafe {
        std::env::remove_var(TEST_TOKEN_ENV);
    }
}

#[tokio::test]
async fn bearer_auth_rejects_wrong_token() {
    const ENV: &str = "QUIK_E2E_ADMIN_TOKEN_WRONG";
    unsafe {
        std::env::set_var(ENV, "correct-token");
    }
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy_with_admin_auth(
        ProxySpec {
            pools: vec![Backends::http("pool-a", vec![backend.addr])],
            routes: vec![route("/", "pool-a")],
        },
        quik::config::AdminAuthGroups {
            read: quik::config::AdminAuthConfig::None,
            write: quik::config::AdminAuthConfig::BearerToken {
                token_env: ENV.to_string(),
            },
        },
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(admin_url(proxy.admin_addr, "/admin/pools/pool-a/members"))
        .header("authorization", "Bearer wrong-token")
        .json(&serde_json::json!({"address": "127.0.0.1:1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    unsafe {
        std::env::remove_var(ENV);
    }
}

#[tokio::test]
async fn bearer_auth_accepts_correct_token() {
    const ENV: &str = "QUIK_E2E_ADMIN_TOKEN_OK";
    const TOKEN: &str = "the-correct-one";
    unsafe {
        std::env::set_var(ENV, TOKEN);
    }
    let backend = Backend::spawn("a").await;
    let backend_b = Backend::spawn("b").await;
    let proxy = spawn_proxy_with_admin_auth(
        ProxySpec {
            pools: vec![Backends::http("pool-a", vec![backend.addr])],
            routes: vec![route("/", "pool-a")],
        },
        quik::config::AdminAuthGroups {
            read: quik::config::AdminAuthConfig::None,
            write: quik::config::AdminAuthConfig::BearerToken {
                token_env: ENV.to_string(),
            },
        },
    )
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .post(admin_url(proxy.admin_addr, "/admin/pools/pool-a/members"))
        .header("authorization", format!("Bearer {TOKEN}"))
        .json(&serde_json::json!({
            "address": backend_b.addr.to_string(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    unsafe {
        std::env::remove_var(ENV);
    }
}

#[tokio::test]
async fn read_endpoints_remain_open_when_only_write_is_authed() {
    const ENV: &str = "QUIK_E2E_ADMIN_TOKEN_READ_OPEN";
    unsafe {
        std::env::set_var(ENV, "doesnt-matter");
    }
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy_with_admin_auth(
        ProxySpec {
            pools: vec![Backends::http("pool-a", vec![backend.addr])],
            routes: vec![route("/", "pool-a")],
        },
        quik::config::AdminAuthGroups {
            read: quik::config::AdminAuthConfig::None,
            write: quik::config::AdminAuthConfig::BearerToken {
                token_env: ENV.to_string(),
            },
        },
    )
    .await;

    let client = reqwest::Client::new();
    // GET without auth — should succeed because read is None.
    let resp = client
        .get(admin_url(proxy.admin_addr, "/admin/pools"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    unsafe {
        std::env::remove_var(ENV);
    }
}

// ── Source provenance + config snapshot ─────────────────────────────────────

#[tokio::test]
async fn member_source_field_distinguishes_config_from_runtime() {
    let backend_a = Backend::spawn("a").await;
    let backend_b = Backend::spawn("b").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![Backends::http("pool-a", vec![backend_a.addr])],
        routes: vec![route("/", "pool-a")],
    })
    .await;

    let client = reqwest::Client::new();
    // Config-origin member.
    let resp = client
        .get(admin_url(
            proxy.admin_addr,
            &format!(
                "/admin/pools/pool-a/members/{}",
                urlencode(&backend_a.addr.to_string())
            ),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["source"], "config");

    // Add a runtime member; the response and a follow-up GET should both
    // report source=runtime.
    let resp = client
        .post(admin_url(proxy.admin_addr, "/admin/pools/pool-a/members"))
        .json(&serde_json::json!({ "address": backend_b.addr.to_string() }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["source"], "runtime");

    let resp = client
        .get(admin_url(
            proxy.admin_addr,
            &format!(
                "/admin/pools/pool-a/members/{}",
                urlencode(&backend_b.addr.to_string())
            ),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["source"], "runtime");
}

#[tokio::test]
async fn config_snapshot_renders_upstream_pools_with_provenance() {
    let backend_a = Backend::spawn("a").await;
    let backend_b = Backend::spawn("b").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![Backends::http("pool-a", vec![backend_a.addr])],
        routes: vec![route("/", "pool-a")],
    })
    .await;

    let client = reqwest::Client::new();
    // Add a runtime member so the snapshot has one of each kind.
    let resp = client
        .post(admin_url(proxy.admin_addr, "/admin/pools/pool-a/members"))
        .json(&serde_json::json!({ "address": backend_b.addr.to_string() }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = client
        .get(admin_url(proxy.admin_addr, "/admin/config/snapshot"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/toml")
    );
    let body = resp.text().await.unwrap();
    assert!(body.contains("[[upstreams]]"));
    assert!(body.contains("name = \"pool-a\""));
    assert!(body.contains(&backend_a.addr.to_string()));
    assert!(body.contains(&backend_b.addr.to_string()));
    // Provenance comments — backend_a came from config, backend_b from runtime.
    let line_a = body
        .lines()
        .find(|l| l.contains(&backend_a.addr.to_string()))
        .unwrap();
    let line_b = body
        .lines()
        .find(|l| l.contains(&backend_b.addr.to_string()))
        .unwrap();
    assert!(line_a.contains("source: config"), "got: {line_a}");
    assert!(line_b.contains("source: runtime"), "got: {line_b}");
}

// ── helpers ─────────────────────────────────────────────────────────────────

/// Tiny percent-encoder for socket-addr-style IDs. We only need to encode `:`,
/// `[`, `]` — the characters that appear in IPv4 host:port and IPv6 literals.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b':' => out.push_str("%3A"),
            b'[' => out.push_str("%5B"),
            b']' => out.push_str("%5D"),
            other => out.push(other as char),
        }
    }
    out
}
