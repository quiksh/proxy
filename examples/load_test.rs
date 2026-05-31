//! Closed-loop load generator with latency histogram.
//!
//! Usage:
//!   cargo run --release --example load_test -- <url> [concurrency=32] [duration_secs=10]
//!
//! Reports p50/p90/p99/p999 (µs), max, total requests, errors, and QPS.
//! Accepts self-signed certs (intended for testing the proxy locally).

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use hdrhistogram::Histogram;

struct Args {
    url: String,
    concurrency: usize,
    duration: Duration,
    http1_only: bool,
}

fn parse_args() -> Result<Args> {
    let mut url = None;
    let mut concurrency = 32usize;
    let mut duration_secs = 10u64;
    let mut http1_only = false;

    let mut iter = std::env::args().skip(1).peekable();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--http1" => http1_only = true,
            "-c" | "--concurrency" => {
                concurrency = iter
                    .next()
                    .context("--concurrency needs a value")?
                    .parse()
                    .context("--concurrency must be an integer")?;
            }
            "-d" | "--duration" => {
                duration_secs = iter
                    .next()
                    .context("--duration needs a value (seconds)")?
                    .parse()
                    .context("--duration must be an integer")?;
            }
            other if !other.starts_with('-') && url.is_none() => {
                url = Some(other.to_string());
            }
            other if !other.starts_with('-') => {
                // positional ordering after url: concurrency, duration_secs
                if concurrency == 32 {
                    concurrency = other.parse().unwrap_or(32);
                } else {
                    duration_secs = other.parse().unwrap_or(duration_secs);
                }
            }
            other => anyhow::bail!("unknown arg: {other}"),
        }
    }

    let url =
        url.context("usage: load_test <url> [-c concurrency] [-d duration_secs] [--http1]")?;
    Ok(Args {
        url,
        concurrency,
        duration: Duration::from_secs(duration_secs),
        http1_only,
    })
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = parse_args()?;

    let mut builder = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .pool_max_idle_per_host(args.concurrency)
        .tcp_nodelay(true);
    if args.http1_only {
        builder = builder.http1_only();
    }
    let client = builder.build().context("building client")?;

    // 3 sig figs is plenty; histogram covers 1µs..1 minute.
    let histogram = Arc::new(Mutex::new(
        Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).expect("histogram"),
    ));
    let counter = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));

    let stop_at = Instant::now() + args.duration;
    eprintln!(
        "load_test: url={} concurrency={} duration={:?} http1_only={}",
        args.url, args.concurrency, args.duration, args.http1_only
    );

    let started = Instant::now();
    let mut handles = Vec::with_capacity(args.concurrency);
    for _ in 0..args.concurrency {
        let client = client.clone();
        let url = args.url.clone();
        let histogram = histogram.clone();
        let counter = counter.clone();
        let errors = errors.clone();
        handles.push(tokio::spawn(async move {
            while Instant::now() < stop_at {
                let t = Instant::now();
                match client.get(&url).send().await {
                    Ok(resp) => {
                        let _ = resp.bytes().await;
                        let micros = t.elapsed().as_micros() as u64;
                        let micros = micros.clamp(1, 60_000_000);
                        let _ = histogram.lock().unwrap().record(micros);
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let elapsed = started.elapsed();
    let req = counter.load(Ordering::Relaxed);
    let err = errors.load(Ordering::Relaxed);
    let hist = histogram.lock().unwrap();
    let qps = req as f64 / elapsed.as_secs_f64();

    println!();
    println!("Requests : {req}");
    println!("Errors   : {err}");
    println!("Duration : {:.2}s", elapsed.as_secs_f64());
    println!("QPS      : {qps:.0}");
    println!("Latency  (µs):");
    println!("  p50    : {}", hist.value_at_quantile(0.50));
    println!("  p90    : {}", hist.value_at_quantile(0.90));
    println!("  p99    : {}", hist.value_at_quantile(0.99));
    println!("  p999   : {}", hist.value_at_quantile(0.999));
    println!("  max    : {}", hist.max());

    Ok(())
}
