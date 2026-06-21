---
title: HA reverse proxy
description: "quik in front of pools of backends: host and path routing, health checks, and graceful drain."
---

The setup most people reach for: quik in front of one or more pools of
backends, routing by host and path, with health checks pulling failing
members out of rotation and graceful drain when you replace one.

This guide walks through the moving parts. The
[full config reference](config-reference.md) has every field; this is the
shape and the reasoning.

## The mental model

A quik config has three top-level concepts:

- **Upstreams** - pools of backend instances. Each pool has a load-balancing
  policy and (optionally) health-check settings.
- **Routes** - first-class request matchers (host, method, path) that pick
  which upstream pool serves a given request. Optional modules apply
  per-route timeouts, body limits, prefix rewriting, and JWT auth.
- **Modules** - applied per-route. Currently: `timeout_ms`, `max_body_bytes`,
  `strip_prefix`, `auth`. Each one is absent unless the key is set.

Two listeners run alongside each other:

- `[listener]` - the proxy port. TLS terminated here.
- `[admin]` - `/healthz`, `/metrics`, and (optionally) the
  [admin API](admin-api.md) for online changes.

## Minimal HA config

Two backends, round-robin between them, passive health pulls bad ones out:

```toml
mode = "edge"

[listener]
bind = "0.0.0.0:443"

[listener.tls]
cert_path = "/etc/quik/tls/cert.pem"
key_path  = "/etc/quik/tls/key.pem"

[admin]
bind = "127.0.0.1:9090"

[shutdown]
drain_grace_seconds = 30

[[upstreams]]
name = "api"
balancer = "least_connections"
members = [
    { address = "10.0.0.5:8080" },
    { address = "10.0.0.6:8080" },
]

[[routes]]
hosts = ["api.example.com"]
path_prefix = "/"
upstream = "api"
```

That's a fully working HA reverse proxy. Everything below is optional
tightening.

## Routing

A request matches a route when every matcher present on the route matches.
A route with no matchers matches everything - useful as a catchall.

| Matcher        | Meaning                                                       |
|----------------|---------------------------------------------------------------|
| `hosts`        | Array of hostnames. `*.example.com` matches subdomains, not the apex. |
| `host`         | Singular alias for a 1-element `hosts`.                       |
| `methods`      | Array of HTTP methods. Empty = any.                           |
| `method`       | Singular alias.                                               |
| `path_exact`   | Exact path match. Beats any prefix.                           |
| `path_prefix`  | Segment-aware. `/api` matches `/api/x` but never `/apifoo`.   |

When multiple routes could match a request, quik picks the most specific:
**exact paths beat all prefixes; longer prefixes beat shorter ones.** Within
a tie, the order in the config file decides.

## Load balancing

Three balancers, picked per pool:

| Balancer            | Cost per pick     | When to use                                                                 |
|---------------------|-------------------|-----------------------------------------------------------------------------|
| `round_robin`       | One `fetch_add`   | Default. Backends are roughly homogeneous; even distribution matters more than tail latency. |
| `random`            | One multiplicative hash | Same cost as round-robin, no shared counter across CPUs - useful at very high QPS where the round-robin atomic is contended. |
| `least_connections` | One pool scan     | Backends have heterogeneous response times. The LB steers away from slow ones automatically because their in-flight counts climb. |

All three skip ejected members (see passive health, below). Inflight
counters increment **before `pick()` returns**, so concurrent picks see each
other and can't stampede the same backend.

## Passive health

On by default. Each backend tracks `consecutive_failures`; any 5xx, connect
error, or timeout increments, any 2xx/3xx/4xx resets. When the counter
crosses `ejection_threshold`, the backend is removed from rotation for an
exponentially-growing window:

```toml
[upstreams.health]
ejection_threshold = 5          # consecutive failures before ejection
ejection_base_ms   = 1000       # initial cool-off
ejection_max_ms    = 60000      # exponential backoff cap
```

After the window expires, the next pick acts as a half-open probe - one
request hits the backend. Success clears the ejection state. Failure
doubles the backoff (1s → 2s → 4s → … capped at `ejection_max_ms`).

If every member of a pool is currently ejected, the proxy returns
`503 - no upstream available` and increments
`quik_proxy_errors_total{kind="no_eligible_upstream"}`.

Every ejection is logged at WARN and counted in
`quik_upstream_ejections_total{pool,member}`.

## Active health

Optional. When enabled, a single task per pool sends HTTP probes to each
member at a fixed interval. Probe traffic does not count toward request
metrics - it lives entirely under `quik_active_health_check_*`.

```toml
[upstreams.active_health]
enabled             = true
path                = "/healthz"
method              = "GET"
interval_ms         = 10_000
timeout_ms          = 2_000
healthy_threshold   = 2
unhealthy_threshold = 3
expected_status     = 200           # or "200-299"
initial_state       = "unhealthy"   # or "healthy"
```

Active and passive health are orthogonal - a backend has to pass both checks
to be eligible. `initial_state = "unhealthy"` is the pessimistic default:
backends don't take traffic until the probe confirms they're up. Switch to
`"healthy"` if downtime is more expensive than the risk of routing briefly
to a backend that hasn't quite started.

## Modules

Each route can opt into one or more of these:

| Module           | What it does                                                | Where it runs |
|------------------|-------------------------------------------------------------|---------------|
| `strip_prefix`   | Removes the prefix from the path forwarded to the backend.  | Before upstream connect. |
| `timeout_ms`     | Bounds upstream response time; 504 on expiry.               | Wraps the upstream call. |
| `max_body_bytes` | Rejects oversized uploads (pre-checks `Content-Length`).    | Before upstream connect. |
| `auth`           | JWT validation against a named `[[auth]]` block.            | Before upstream connect. |

Example combining all four:

```toml
[[routes]]
hosts          = ["api.example.com"]
methods        = ["POST"]
path_prefix    = "/api/v1/billing"
strip_prefix   = "/api/v1"
max_body_bytes = 1_048_576    # 1 MiB
timeout_ms     = 30_000
auth           = "main"
upstream       = "billing-api"
```

A `POST` to `/api/v1/billing/charges` larger than 1 MiB is rejected with 413
before quik even contacts the backend. A token failure returns 401/403.
Anything else gets forwarded to `billing-api` as `/billing/charges`.

## HTTP/2 backends

quik's inbound listener negotiates h1 or h2 with the client via ALPN. The
proxy→backend hop is independent; set `http_version` on the pool to opt in
to h2:

```toml
[[upstreams]]
name = "grpc-svc"
http_version = "h2"
members = [{ address = "grpc.internal:443", scheme = "https" }]
```

Use h2 only for backends you've verified can speak HTTP/2 - most legacy HTTP
services can't. The default is `h1` for compatibility.

## JWT authentication

Define `[[auth]]` blocks at the top level. Routes opt in via
`auth = "<name>"`:

```toml
[[auth]]
name            = "main"
jwks_url        = "https://issuer.example.com/.well-known/jwks.json"
issuer          = "https://issuer.example.com/"
audience        = "users-api"
algorithms      = ["RS256", "EdDSA"]
required_claims = ["sub"]

inject_headers = [
    { claim = "sub",       header = "x-auth-sub" },
    { claim = "tenant_id", header = "x-tenant-id", required = true },
]
```

The JWKS is cached after first fetch; an unknown `kid` triggers a
non-blocking refresh.

Per-request behaviour:

- No `Authorization: Bearer …` → `401` with `WWW-Authenticate: Bearer`
- Bad signature / unknown `kid` / disallowed algorithm → `401`
- Wrong `iss`/`aud`/`exp`, missing required claim → `403`
- A reserved header was set on the inbound request → `403` with
  `outcome="spoofed_header"` in metrics

Reserved headers are exactly the ones listed under `inject_headers`. Setting
one on the inbound request is rejected - quik refuses to silently overwrite
them. This catches both deliberate spoofing and accidental forwarding from
an upstream-of-upstream proxy.

The full multi-auth example with mintable test tokens is in
`config/auth-demo.toml`. See [docs/admin-api.md](admin-api.md) for the
admin-listener auth modes (separate from these `[[auth]]` blocks).

## Identity headers

On every forwarded request, quik adds:

| Header              | Source                                                                              |
|---------------------|-------------------------------------------------------------------------------------|
| `X-Request-ID`      | Inbound header honoured only from a *trusted* peer; otherwise replaced with a generated id (CSPRNG, 16 bytes). |
| `traceparent`       | Inbound header honoured only from a *trusted* peer **and** when it is valid W3C format; otherwise generated. |
| `X-Forwarded-For`   | `mode = "edge"`: replaces inbound. `mode = "host"`: appends client IP to the chain. |
| `X-Forwarded-Host`  | The `Host` header the client sent.                                                  |
| `X-Forwarded-Proto` | `https` (inbound is always TLS).                                                    |

A peer is *trusted* by the same rule the forwarding headers use: `mode = "host"`,
or `mode = "edge"` with the immediate peer inside `[forwarded].trusted_proxies`.
So the correlation identifiers (`X-Request-ID`, `traceparent`) follow the same
trust model as `X-Forwarded-For`: a value from a trusted peer is propagated
end-to-end (so an upstream CDN/LB/gateway can set the id and have quik's logs
share it), but a value from an untrusted edge client is discarded and a fresh
one generated. That stops an open-internet client from poisoning correlation
(reusing or forging another request's id) or forcing trace sampling via an
injected `traceparent`.

`mode = "edge"` is the right default when quik sits at the network boundary
- it normalises whatever a client might have sent. Use `mode = "host"` when
quik runs behind another L7 proxy (e.g. an AWS ALB) and you want to extend
its forwarded chain rather than replace it.

## Observability

Metrics on the admin listener at `/metrics`. The interesting ones:

| Metric                                | Type    | Labels              |
|---------------------------------------|---------|---------------------|
| `quik_requests_total`                 | counter | `route`, `status`   |
| `quik_request_duration_ms`            | histogram | `route`           |
| `quik_upstream_selected_total`        | counter | `pool`, `member`    |
| `quik_upstream_bytes_sent_total`      | counter | `pool`, `member`    |
| `quik_upstream_bytes_received_total`  | counter | `pool`, `member`    |
| `quik_upstream_inflight`              | gauge   | `pool`, `member`    |
| `quik_upstream_ejections_total`       | counter | `pool`, `member`    |
| `quik_pool_members_total`             | gauge   | `pool`, `state`     |
| `quik_active_health_check_total`      | counter | `pool`, `member`, `result` |
| `quik_auth_total`                     | counter | `block`, `outcome`  |

Logs: one access event per completed request at `target = quik::access`,
INFO level, carrying `method`, `path`, `peer`, `request_id`, `status`,
`duration_ms`, `route`, `upstream`. JSON by default; switch to
`format = "key_value"` for human eyes. Filter the access feed independently
with `RUST_LOG="off,quik::access=info"`.

## Graceful shutdown

`SIGTERM` or first `SIGINT`: stop accepting, `/healthz` returns 503,
in-flight requests get up to `shutdown.drain_grace_seconds` to complete.

A second signal during drain: force exit. In-flight requests are aborted.
Useful when something is wedged and you don't want to wait the rest of the
grace period.

```rust
let coord = Coordinator::new(30);
coord.install_signal_handlers();
match coord.wait_for_exit().await {
    ExitReason::DrainComplete => { /* clean */ }
    ExitReason::Forced        => { /* second signal */ }
}
```

## Deployment patterns

**Behind a TCP load balancer.** Run two or more quik instances behind a TCP
LB (an ELB/NLB, HAProxy, keepalived/LVS). Each instance terminates TLS
locally; the LB doesn't need to. Configure both with the same upstream pool
list. Use `mode = "host"` if the LB itself sets `X-Forwarded-For`.

**Behind a managed L7 LB (ALB, Cloudflare).** Same idea, but the outer LB
also speaks HTTP and is doing the certificate management. Set
`mode = "host"` so quik appends to the LB's `X-Forwarded-For` chain
instead of overwriting it.

**Rolling backend deploys.** Use the [admin API](admin-api.md) - drain old
members, observe `/admin/pools/{pool}` until they're empty, add new ones,
delete the drained ones. No proxy restart, no dropped requests.

**Active-passive failover.** Run two proxies; only one has the floating
IP / DNS record at a time. quik has no shared state, so the standby can
take over immediately. The `/healthz` endpoint (which returns 503 during
drain) is the right thing for keepalived or a TCP healthcheck to watch.

## What to read next

- [Admin API](admin-api.md) - add/drain/remove members on a running proxy.
- [Hardening](hardening.md) - defensive timeouts and limits for direct-to-public deployments.
- [Config reference](config-reference.md) - every field, every default.
- [Forward proxy](forward-proxy.md) - same binary, second role.
