//! Active health checks — probe state transitions and the canonical
//! passive/active interaction.
//!
//! Probe interval is set to 100ms with `unhealthy_threshold=1`,
//! `healthy_threshold=1` so transitions fire on the first probe. Tests poll
//! the admin API for state rather than using fixed sleeps where possible.

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use http::StatusCode;
use quik::config::{
    ActiveHealthConfig, BalancerKind, InitialActiveState, StatusMatcher, UpstreamHealthConfig,
};
use serde_json::Value;

use common::{Backend, Backends, ProxySpec, https_client, route, spawn_proxy};

fn admin_url(addr: SocketAddr, path: &str) -> String {
    format!("http://{addr}{path}")
}

fn proxy_url(addr: SocketAddr, path: &str) -> String {
    format!("https://localhost:{}{}", addr.port(), path)
}

fn fast_active_health(initial: InitialActiveState) -> ActiveHealthConfig {
    ActiveHealthConfig {
        enabled: true,
        path: "/healthz".to_string(),
        method: "GET".to_string(),
        interval_ms: 100,
        timeout_ms: 1_000,
        healthy_threshold: 1,
        unhealthy_threshold: 1,
        expected_status: StatusMatcher::Exact(200),
        initial_state: initial,
    }
}

fn urlencode(s: &str) -> String {
    s.replace(':', "%3A")
        .replace('[', "%5B")
        .replace(']', "%5D")
}

async fn wait_for_state<F>(
    client: &reqwest::Client,
    proxy_admin: SocketAddr,
    pool: &str,
    member: &str,
    pred: F,
) where
    F: Fn(&Value) -> bool,
{
    let encoded = urlencode(member);
    let url = admin_url(
        proxy_admin,
        &format!("/admin/pools/{pool}/members/{encoded}"),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if Instant::now() > deadline {
            // Last response for diagnostic context.
            let r = client.get(&url).send().await.unwrap();
            let body: Value = r.json().await.unwrap();
            panic!("predicate never satisfied; last state: {body:#}");
        }
        let r = client.get(&url).send().await.unwrap();
        let body: Value = r.json().await.unwrap();
        if pred(&body) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ── Pessimistic startup ─────────────────────────────────────────────────────

#[tokio::test]
async fn pessimistic_startup_member_becomes_routable_after_probe_succeeds() {
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![
            Backends::http("pool-a", vec![backend.addr])
                .with_active_health(fast_active_health(InitialActiveState::Unhealthy)),
        ],
        routes: vec![route("/", "pool-a")],
    })
    .await;
    let client = reqwest::Client::new();
    let id = backend.addr.to_string();

    // Before the first probe fires: should be unroutable.
    let r = client
        .get(admin_url(
            proxy.admin_addr,
            &format!("/admin/pools/pool-a/members/{}", urlencode(&id)),
        ))
        .send()
        .await
        .unwrap();
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["active"]["state"], "unhealthy");

    // Wait for a probe to land and flip state to healthy.
    wait_for_state(&client, proxy.admin_addr, "pool-a", &id, |b| {
        b["routable"] == true && b["active"]["state"] == "healthy"
    })
    .await;

    // Backend should have seen at least one probe hit.
    assert!(backend.healthz_count() >= 1);
}

// ── Active failure removes from routing ─────────────────────────────────────

#[tokio::test]
async fn member_becomes_unroutable_after_probe_fails() {
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![
            Backends::http("pool-a", vec![backend.addr])
                // Optimistic startup — member is routable immediately; we then flip
                // the backend to 503 and observe the transition out.
                .with_active_health(fast_active_health(InitialActiveState::Healthy)),
        ],
        routes: vec![route("/", "pool-a")],
    })
    .await;
    let client = reqwest::Client::new();
    let id = backend.addr.to_string();

    // Wait for first successful probe so we know the loop is alive.
    wait_for_state(&client, proxy.admin_addr, "pool-a", &id, |b| {
        b["active"]["consecutive_ok"].as_u64().unwrap_or(0) >= 1
    })
    .await;

    // Flip /healthz to 503.
    backend.set_healthz_status(503);

    // Wait for transition to unhealthy.
    wait_for_state(&client, proxy.admin_addr, "pool-a", &id, |b| {
        b["active"]["state"] == "unhealthy" && b["routable"] == false
    })
    .await;
}

#[tokio::test]
async fn member_recovers_after_probe_succeeds_again() {
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![
            Backends::http("pool-a", vec![backend.addr])
                .with_active_health(fast_active_health(InitialActiveState::Healthy)),
        ],
        routes: vec![route("/", "pool-a")],
    })
    .await;
    let client = reqwest::Client::new();
    let id = backend.addr.to_string();

    // Burst-fail the backend: flip immediately so we don't depend on the
    // first probe firing before the toggle.
    backend.set_healthz_status(503);
    wait_for_state(&client, proxy.admin_addr, "pool-a", &id, |b| {
        b["active"]["state"] == "unhealthy"
    })
    .await;

    // Recover.
    backend.set_healthz_status(200);
    wait_for_state(&client, proxy.admin_addr, "pool-a", &id, |b| {
        b["active"]["state"] == "healthy" && b["routable"] == true
    })
    .await;
}

// ── The canonical interaction: passive backoff overrides active healthy ─────

#[tokio::test]
async fn passive_ejection_keeps_member_out_even_when_active_probes_pass() {
    // Backend: returns 500 on real traffic, 200 on /healthz. So passive
    // health observes failures on the request path and ejects; active health
    // continues to pass because /healthz is fine. routable() should still
    // be false during the passive backoff window.
    let backend = Backend::spawn_with_status("a", StatusCode::INTERNAL_SERVER_ERROR).await;
    let backend_alt = Backend::spawn("alt").await; // a second member so requests can still complete

    // Threshold of 2 failures to eject; backoff base 5s so the window is wide
    // enough that we can clearly observe the "still ejected" state.
    let health = UpstreamHealthConfig {
        ejection_threshold: 2,
        ejection_base_ms: 5_000,
        ejection_max_ms: 60_000,
    };

    let proxy = spawn_proxy(ProxySpec {
        pools: vec![
            Backends::http("pool-a", vec![backend.addr, backend_alt.addr])
                .with_health(health)
                .with_active_health(fast_active_health(InitialActiveState::Healthy))
                .with_balancer(BalancerKind::RoundRobin),
        ],
        routes: vec![route("/", "pool-a")],
    })
    .await;
    let client = reqwest::Client::new();
    let id = backend.addr.to_string();

    // Drive real traffic — RoundRobin will hit backend a few times, ejecting it.
    let proxy_client = https_client();
    for _ in 0..6 {
        let _ = proxy_client
            .get(proxy_url(proxy.addr, "/work"))
            .send()
            .await
            .unwrap();
    }

    // Backend should now be passively ejected — passive.ejected = true.
    wait_for_state(&client, proxy.admin_addr, "pool-a", &id, |b| {
        b["passive"]["ejected"] == true
    })
    .await;

    // Wait long enough for active probes to land successfully (they hit
    // /healthz which still returns 200) and confirm active=healthy.
    wait_for_state(&client, proxy.admin_addr, "pool-a", &id, |b| {
        b["active"]["state"] == "healthy"
    })
    .await;

    // Now the key assertion: passive ejected + active healthy → still unroutable.
    let r = client
        .get(admin_url(
            proxy.admin_addr,
            &format!("/admin/pools/pool-a/members/{}", urlencode(&id)),
        ))
        .send()
        .await
        .unwrap();
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["passive"]["ejected"], true);
    assert_eq!(body["active"]["state"], "healthy");
    assert_eq!(
        body["routable"], false,
        "passive backoff must keep member out even when active probes pass: {body:#}"
    );
}

// ── Drain pauses probes ─────────────────────────────────────────────────────

#[tokio::test]
async fn drain_pauses_active_probes() {
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![
            Backends::http("pool-a", vec![backend.addr])
                .with_active_health(fast_active_health(InitialActiveState::Healthy))
                .with_drain_timeout_ms(10_000),
        ],
        routes: vec![route("/", "pool-a")],
    })
    .await;
    let client = reqwest::Client::new();
    let id = backend.addr.to_string();

    // Let a few probes fire first.
    wait_for_state(&client, proxy.admin_addr, "pool-a", &id, |b| {
        b["active"]["consecutive_ok"].as_u64().unwrap_or(0) >= 2
    })
    .await;
    let count_before = backend.healthz_count();

    // Drain (don't remove — we want to keep the member around to observe
    // that probes don't continue).
    client
        .post(admin_url(
            proxy.admin_addr,
            &format!("/admin/pools/pool-a/members/{}/drain", urlencode(&id)),
        ))
        .send()
        .await
        .unwrap();

    // Give plenty of probe-intervals' worth of time. If probes were still
    // firing, healthz_count would grow.
    tokio::time::sleep(Duration::from_millis(600)).await;
    let count_after = backend.healthz_count();
    let new_probes = count_after.saturating_sub(count_before);
    assert!(
        new_probes <= 1,
        "probes should pause on drain; before={count_before} after={count_after} (got {new_probes} new probes)"
    );
}

// ── Probe metrics are emitted ───────────────────────────────────────────────

#[tokio::test]
async fn active_health_check_metrics_are_emitted() {
    let backend = Backend::spawn("a").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![
            Backends::http("pool-a", vec![backend.addr])
                .with_active_health(fast_active_health(InitialActiveState::Unhealthy)),
        ],
        routes: vec![route("/", "pool-a")],
    })
    .await;
    let client = reqwest::Client::new();
    let id = backend.addr.to_string();
    // Wait for at least one probe to fire.
    wait_for_state(&client, proxy.admin_addr, "pool-a", &id, |b| {
        b["active"]["consecutive_ok"].as_u64().unwrap_or(0) >= 1
    })
    .await;
    let metrics = client
        .get(admin_url(proxy.admin_addr, "/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains("quik_active_health_check_total"),
        "missing active health counter in /metrics output"
    );
    assert!(
        metrics.contains("result=\"success\""),
        "no success-labelled probe counted: {metrics}"
    );
    // Probe→forward isolation is a code-level guarantee (probe.rs uses
    // pool.client.request directly, not the Balancer::pick path); we don't
    // re-assert it here because /metrics is a process-global registry and
    // earlier tests in this binary may have driven real traffic that would
    // legitimately show up under quik_upstream_selected_total. The
    // structural test of the metric namespace separation is implicit in
    // those earlier tests passing with their own assertions.
}
