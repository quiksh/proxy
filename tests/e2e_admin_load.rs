//! Admin load test — add and remove members while sustained traffic flows.
//!
//! Validates the lock-free Arc-slice swap inside `UpstreamPoolEntry.members`.
//! A failure here would manifest as 5xx (the proxy returned no_eligible_upstream
//! mid-swap) or connect errors (a connection landed on a slice we just
//! freed). The design intent is that neither can happen.
//!
//! Kept light (~1k requests in ~3 seconds) so CI runs in a reasonable budget.
//! The signal is the same as a longer run — the swap is either correct or
//! it isn't.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use http::StatusCode;
use serde_json::json;

use common::{Backend, Backends, ProxySpec, https_client, route, spawn_proxy};

fn proxy_url(addr: SocketAddr, path: &str) -> String {
    format!("https://localhost:{}{}", addr.port(), path)
}

fn admin_url(addr: SocketAddr, path: &str) -> String {
    format!("http://{addr}{path}")
}

fn urlencode(s: &str) -> String {
    s.replace(':', "%3A")
        .replace('[', "%5B")
        .replace(']', "%5D")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn add_and_remove_under_traffic_with_zero_failed_requests() {
    // Two initial members. Mid-stream we add a third and then drain one of
    // the originals. Throughout, the client should observe zero 5xx and zero
    // connect errors.
    let a = Backend::spawn("a").await;
    let b = Backend::spawn("b").await;
    let c = Backend::spawn("c").await;
    let proxy = spawn_proxy(ProxySpec {
        pools: vec![Backends::http("pool", vec![a.addr, b.addr]).with_drain_timeout_ms(3_000)],
        routes: vec![route("/", "pool")],
    })
    .await;

    let total_requests = Arc::new(AtomicU64::new(0));
    let failures_5xx = Arc::new(AtomicU64::new(0));
    let connect_errors = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    // Spawn N concurrent workers, each looping until `stop` is set. The
    // stop flag is checked between requests — no inner-loop polling timers.
    let worker_count = 16;
    let mut workers = Vec::new();
    for _ in 0..worker_count {
        let total = total_requests.clone();
        let f5xx = failures_5xx.clone();
        let connect_err = connect_errors.clone();
        let stop = stop.clone();
        let client = https_client();
        let addr = proxy.addr;
        workers.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                match client.get(proxy_url(addr, "/work")).send().await {
                    Ok(r) => {
                        total.fetch_add(1, Ordering::Relaxed);
                        if r.status().is_server_error() {
                            f5xx.fetch_add(1, Ordering::Relaxed);
                        }
                        // Drain the body so the connection can be reused.
                        let _ = r.bytes().await;
                    }
                    Err(_) => {
                        total.fetch_add(1, Ordering::Relaxed);
                        connect_err.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    // Let traffic flow for a moment, then add c.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let admin = reqwest::Client::new();
    let resp = admin
        .post(admin_url(proxy.admin_addr, "/admin/pools/pool/members"))
        .json(&json!({"address": c.addr.to_string(), "scheme": "http"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // More traffic, then drain a.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let resp = admin
        .delete(admin_url(
            proxy.admin_addr,
            &format!(
                "/admin/pools/pool/members/{}",
                urlencode(&a.addr.to_string())
            ),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // Hold traffic until a is fully removed (poll the admin API).
    let removal_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if Instant::now() > removal_deadline {
            panic!("member a was never removed from the pool");
        }
        let r = admin
            .get(admin_url(
                proxy.admin_addr,
                &format!(
                    "/admin/pools/pool/members/{}",
                    urlencode(&a.addr.to_string())
                ),
            ))
            .send()
            .await
            .unwrap();
        if r.status() == StatusCode::NOT_FOUND {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // One more burst of traffic after removal completes.
    tokio::time::sleep(Duration::from_millis(500)).await;
    stop.store(true, Ordering::Relaxed);
    for w in workers {
        let _ = w.await;
    }

    let total = total_requests.load(Ordering::Relaxed);
    let f5xx = failures_5xx.load(Ordering::Relaxed);
    let cerr = connect_errors.load(Ordering::Relaxed);

    println!(
        "load test summary: total={total} 5xx={f5xx} connect_err={cerr} \
         backend_a={} backend_b={} backend_c={}",
        a.calls().len(),
        b.calls().len(),
        c.calls().len(),
    );

    assert!(total > 100, "barely any traffic flowed ({total})");
    assert_eq!(f5xx, 0, "expected 0 5xx responses, got {f5xx}");
    assert_eq!(cerr, 0, "expected 0 connect errors, got {cerr}");

    // Sanity: all three backends saw work. (a was added at start + removed
    // mid-stream, c was added mid-stream — both should have traffic.)
    assert!(
        !a.calls().is_empty(),
        "backend a saw no traffic before drain"
    );
    assert!(!b.calls().is_empty(), "backend b saw no traffic");
    assert!(!c.calls().is_empty(), "backend c saw no traffic after add");
}
