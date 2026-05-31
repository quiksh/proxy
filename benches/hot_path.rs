use criterion::{Criterion, black_box, criterion_group, criterion_main};
use http::header::{ACCEPT, ACCEPT_ENCODING, CONNECTION, HOST, USER_AGENT};
use http::{HeaderMap, HeaderValue, Method};

use quik::config::RouteConfig;
use quik::headers::strip_hop_by_hop;
use quik::routing::RoutingTable;

fn make_table(n: usize) -> RoutingTable {
    let mut routes = Vec::with_capacity(n);
    for i in 0..n {
        routes.push(RouteConfig {
            hosts: vec![format!("svc-{i}.internal")],
            path_prefix: Some(format!("/api/v{}/items/{}", i % 5, i)),
            upstream: format!("pool-{i}"),
            ..Default::default()
        });
    }
    // Add a catchall so 'miss' tests still don't trivially short-circuit.
    routes.push(RouteConfig {
        path_prefix: Some("/".to_string()),
        upstream: "catchall".to_string(),
        ..Default::default()
    });
    RoutingTable::from_routes(&routes).unwrap()
}

fn bench_route_match(c: &mut Criterion) {
    let mut g = c.benchmark_group("route_match");
    let table = make_table(50);
    let method = Method::GET;

    g.bench_function("hit_50routes", |b| {
        b.iter(|| {
            black_box(table.match_request(
                black_box(Some("svc-25.internal")),
                black_box(&method),
                black_box("/api/v0/items/25/42"),
            ))
        });
    });

    g.bench_function("hit_first_route_50routes", |b| {
        // Longest-prefix-first sort means the most specific route ends up early.
        b.iter(|| {
            black_box(table.match_request(
                black_box(Some("svc-49.internal")),
                black_box(&method),
                black_box("/api/v4/items/49/99"),
            ))
        });
    });

    g.bench_function("catchall_50routes", |b| {
        b.iter(|| {
            black_box(table.match_request(
                black_box(Some("nope.example")),
                black_box(&method),
                black_box("/unmatched/path/here"),
            ))
        });
    });

    g.finish();
}

fn bench_header_strip(c: &mut Criterion) {
    fn typical_request_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(HOST, HeaderValue::from_static("api.example.com"));
        h.insert(
            USER_AGENT,
            HeaderValue::from_static("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"),
        );
        h.insert(
            ACCEPT,
            HeaderValue::from_static("text/html,application/json;q=0.9,*/*;q=0.8"),
        );
        h.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        h.insert(
            "accept-language",
            HeaderValue::from_static("en-GB,en;q=0.9"),
        );
        h.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
        h.insert("upgrade-insecure-requests", HeaderValue::from_static("1"));
        h.insert(
            "authorization",
            HeaderValue::from_static("Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0.payload.sig"),
        );
        h.insert(
            "traceparent",
            HeaderValue::from_static("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
        );
        h.insert("x-request-id", HeaderValue::from_static("abc-123-def-456"));
        h
    }

    let mut g = c.benchmark_group("strip_hop_by_hop");

    g.bench_function("typical_request_headers", |b| {
        b.iter_batched(
            typical_request_headers,
            |mut h| {
                strip_hop_by_hop(black_box(&mut h));
                black_box(h);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    g.finish();
}

criterion_group!(benches, bench_route_match, bench_header_strip);
criterion_main!(benches);
