---
title: Config reference
description: Every TOML option quik accepts, what it does, and its default.
---

The full TOML schema. Most fields have sensible defaults - this page lists
every option, what it does, and what the default is. For commentary and
example deployments, see the scenario guides:

- [Homelab](homelab.md)
- [HA reverse proxy](ha-reverse-proxy.md)
- [Forward proxy](forward-proxy.md)
- [Admin API](admin-api.md)

> **Reloadable at runtime.** `[[routes]]`, `[[auth]]`, and `[forwarded]` can be
> edited and applied to a running proxy without a restart - send `SIGHUP` or
> `POST /admin/config/reload`. Every other section (listener, admin, egress,
> `mode`, `[shutdown]`, `[logging]`, and upstream pool *shape*) is fixed at boot;
> reload rejects a change to any of them rather than applying it partially.
> Upstream pool *membership* is managed separately via the admin API. See
> [Config reload](admin-api.md#config-reload).

## Top-level

```toml
mode = "edge"
```

| Field  | Type     | Default | Notes                                                                 |
|--------|----------|---------|-----------------------------------------------------------------------|
| `mode` | `"edge"` \| `"host"` | `"edge"` | Default trust posture for inbound forwarding headers. `edge`: replace inbound `X-Forwarded-For` (treat it as spoofable). `host`: append to it (we sit behind a trusted LB). See `[forwarded]` to trust specific peers in `edge` mode. |

## `[forwarded]`

Controls how the proxy populates client-forwarding headers. Optional - when
omitted, the mode-driven defaults apply: `X-Forwarded-For`, `X-Forwarded-Proto`
and `X-Forwarded-Host` are always emitted, the inbound `X-Forwarded-For` chain
is trusted only in `host` mode, and the RFC 7239 `Forwarded` header is not
emitted.

```toml
[forwarded]
trusted_proxies = ["10.0.0.0/8", "192.168.1.5"]
emit            = true
```

| Field             | Type             | Default | Notes                                                                                                                                                                 |
|-------------------|------------------|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `trusted_proxies` | array of strings | `[]`    | CIDR blocks (`10.0.0.0/8`) or bare IP literals (`192.168.1.5`, treated as `/32` or `/128`). In `edge` mode, a request whose immediate peer is inside one of these is handled like `host` mode for that request: the inbound `X-Forwarded-For` / `Forwarded` chain is appended to rather than replaced. No effect in `host` mode. A malformed entry fails boot. |
| `emit`            | bool             | `false` | Also emit the RFC 7239 `Forwarded` header (`for=…;host=…;proto=https`) alongside `X-Forwarded-*`. IPv6 `for` nodes are bracketed and quoted per the RFC.                |

The trust model, summarised:

| Mode   | `trusted_proxies` match | Behaviour                                  |
|--------|-------------------------|--------------------------------------------|
| `edge` | no                      | Replace the inbound chain with the peer IP |
| `edge` | yes                     | Append the peer IP to the inbound chain    |
| `host` | (ignored)               | Append the peer IP to the inbound chain    |

The same trust decision also governs the correlation identity headers
`X-Request-ID` and `traceparent`: honoured when they arrive from a trusted peer,
regenerated when they arrive from an untrusted edge client. See
[Identity headers](ha-reverse-proxy.md#identity-headers).

## Environment variable expansion

Strings of the form `${VAR}` or `${VAR:-default}` are expanded from the
proxy's environment before TOML parsing. Expansion runs on the raw text,
so the same syntax in a comment is also expanded - keep `${…}` out of
comments unless you want it substituted.

A missing `${VAR}` with no default fails boot loudly.

## `[listener]`

The inbound proxy listener.

```toml
[listener]
bind = "0.0.0.0:443"

[listener.tls]
cert_path = "/etc/quik/tls/cert.pem"
key_path  = "/etc/quik/tls/key.pem"
```

| Field             | Type     | Required | Notes                                       |
|-------------------|----------|----------|---------------------------------------------|
| `bind`            | socket   | yes      | `host:port` or `[ipv6]:port`.               |
| `tls.cert_path`   | path     | yes      | PEM cert (chain).                           |
| `tls.key_path`    | path     | yes      | PEM private key.                            |
| `limits`          | table    | no       | See [`[listener.limits]`](#listenerlimits). |

ALPN advertises `h2` and `http/1.1`.

### `[listener.limits]`

Defensive connection-level timeouts and HTTP/2 caps. See
[hardening.md](hardening.md) for picking values per deployment.

| Field                                | Type | Default   | Notes                                              |
|--------------------------------------|------|-----------|----------------------------------------------------|
| `header_read_timeout_ms`             | u64  | `30_000`  | Slowloris mitigation. `0` disables.                |
| `http2_keep_alive_interval_ms`       | u64  | `0`       | PING interval for idle h2 connections. `0` disables. |
| `http2_keep_alive_timeout_ms`        | u64  | `20_000`  | PING response deadline; meaningful only when interval > 0. |
| `http2_max_concurrent_streams`       | u32  | `256`     | Per-connection stream cap.                         |
| `http2_max_pending_accept_reset_streams` | usize| `20`  | Rapid-reset (CVE-2023-44487) mitigation: client-reset streams awaiting acceptance before `GOAWAY`. `0` defers to hyper's default. |
| `websocket_idle_timeout_ms`          | u64  | `300_000` | Close WS tunnels with no traffic in either direction. `0` disables. |

## `[admin]`

The admin listener - `/healthz`, `/metrics`, and the `/admin/pools` API.

```toml
[admin]
bind = "127.0.0.1:9090"

[admin.tls]                            # optional
cert_path      = "./tls/admin-cert.pem"
key_path       = "./tls/admin-key.pem"
client_ca_path = "./tls/admin-client-ca.pem"   # required for mtls auth

[admin.auth.read]                      # default: { mode = "none" }
mode = "none"

[admin.auth.write]                     # default: { mode = "none" }
mode      = "bearer_token"
token_env = "QUIK_ADMIN_TOKEN"
```

| Field          | Type   | Default            | Notes                                                                |
|----------------|--------|--------------------|----------------------------------------------------------------------|
| `bind`         | socket | required           | Loopback is the right default for an unauthed admin.                 |
| `tls.*`        | TLS    | absent             | Required when any auth group is `mtls`.                              |
| `auth.read`    | auth   | `{mode="none"}`    | Applies to `GET` / `HEAD`.                                           |
| `auth.write`   | auth   | `{mode="none"}`    | Applies to `POST` / `DELETE`. Strongly recommended in production.    |

### Auth modes

```toml
mode = "none"
```

```toml
mode      = "bearer_token"
token_env = "QUIK_ADMIN_TOKEN"
```

`token_env` names an environment variable. Empty/missing → boot fails.
Clients send `Authorization: Bearer <token>`.

```toml
mode = "mtls"
```

Requires `[admin.tls].client_ca_path`. The verified cert's SHA-256
fingerprint is the audit principal. The listener becomes TLS-mandatory
whenever any auth group is `mtls`.

## `[shutdown]`

```toml
[shutdown]
drain_grace_seconds     = 30
pre_drain_grace_seconds = 0
```

| Field                     | Default | Notes                                          |
|---------------------------|---------|------------------------------------------------|
| `drain_grace_seconds`     | `30`    | First SIGTERM/SIGINT: stop accepting, allow in-flight up to this long. Second signal: force exit. |
| `pre_drain_grace_seconds` | `0`     | Edge-withdraw grace. On SIGTERM `/healthz` returns 503 immediately but the proxy keeps accepting for this long *before* the drain begins, so a perimeter notices and stops routing first. `0` = disabled. |

## `[logging]`

```toml
[logging]
level            = "info,quik=info"
format           = "json"
client_ip_header = "cf-connecting-ip"
user_agent       = true
```

| Field              | Type                       | Default              | Notes                                          |
|--------------------|----------------------------|----------------------|------------------------------------------------|
| `level`            | RUST_LOG-style env filter  | `"info,quik=info"`   | `RUST_LOG` env overrides if set.               |
| `format`           | `"json"` \| `"key_value"`  | `"json"`             | JSON for shippers, key_value for human eyes.   |
| `client_ip_header` | header name                | unset (off)          | Source header for the `client_ip` access-log field (see below). |
| `user_agent`       | bool                       | `false`              | Emit the `user_agent` access-log field from `User-Agent`. |

### Request-derived access-log fields

These add opt-in, directly-queryable fields to each `quik::access` event
(success and terminal paths alike), instead of a nested blob:

- **`client_ip_header`** names the header carrying the real client address.
  When set and present, its value is logged as the top-level `client_ip` field.
  Behind a CDN the originating address lives in a CDN-specific header -
  `cf-connecting-ip` for Cloudflare, `true-client-ip`, or `x-real-ip`. A
  malformed header name fails boot.
- **`user_agent = true`** logs the request's `User-Agent` as the top-level
  `user_agent` field.

Example access log:

```json
{"target":"quik::access","status":200,"route":"web","client_ip":"203.0.113.7","user_agent":"curl/8","message":"access"}
```

Notes:

- **Querying:** because the field names (`client_ip`, `user_agent`) are fixed,
  they're first-class log fields - no nested JSON to re-parse in your log store.
- **Cost:** both off (the default) does nothing on the request path. Each field
  is a single header lookup when enabled.
- **Security:** values are logged verbatim; these fields are for non-sensitive
  operational headers only.

## `[[upstreams]]`

A pool of backend members.

```toml
[[upstreams]]
name = "api"
balancer = "round_robin"
http_version = "h1"
members = [
    { address = "10.0.0.5:8080" },
    { address = "10.0.0.6:8080", scheme = "https" },
]

[upstreams.tls]
skip_verify = false

[upstreams.health]
ejection_threshold = 5
ejection_base_ms   = 1000
ejection_max_ms    = 60000

[upstreams.active_health]
enabled             = false
path                = "/healthz"
method              = "GET"
interval_ms         = 10000
timeout_ms          = 2000
healthy_threshold   = 2
unhealthy_threshold = 3
expected_status     = 200
initial_state       = "unhealthy"

[upstreams.drain]
timeout_ms = 60000
```

### Pool fields

| Field          | Type                                       | Default          | Notes                                                          |
|----------------|--------------------------------------------|------------------|----------------------------------------------------------------|
| `name`         | string                                     | required         | Referenced from routes via `upstream = "<name>"`.              |
| `members`      | array of `{address, scheme}`               | required, ≥1     | `address` is `host:port`. `scheme` defaults to `"http"`.       |
| `balancer`     | `"round_robin"` \| `"random"` \| `"least_connections"` | `"round_robin"` | See [HA reverse proxy](ha-reverse-proxy.md#load-balancing).        |
| `http_version` | `"h1"` \| `"h2"`                           | `"h1"`           | Proxy→backend version. Set `h2` only for verified-h2 backends. |

### `[upstreams.tls]`

| Field         | Type   | Default | Notes                                                                            |
|---------------|--------|---------|----------------------------------------------------------------------------------|
| `skip_verify` | bool   | `false` | **Danger:** bypass cert verification. OK for trusted internal nets / homelab. |

### `[upstreams.health]` (passive)

| Field                | Type | Default  | Notes                                              |
|----------------------|------|----------|----------------------------------------------------|
| `ejection_threshold` | u32  | `5`      | Consecutive failures (5xx / timeout / connect err). |
| `ejection_base_ms`   | u64  | `1000`   | Initial cool-off window.                            |
| `ejection_max_ms`    | u64  | `60000`  | Exponential cap. Re-admission probe on window end.  |

### `[upstreams.active_health]`

This is quik's **routing/readiness** probe - "should traffic go to this member
right now?" - run by quik itself from its own vantage point, independent of how
the member was added. For NATS-backed pools it is distinct from the registrant's
**liveness** gate (the `quik-register` `[liveness]` section, "should this
instance be in the registry at all?"); see `docs/service-registration.md` §6.

| Field                  | Type                          | Default            | Notes                                                               |
|------------------------|-------------------------------|--------------------|---------------------------------------------------------------------|
| `enabled`              | bool                          | `false`            | Disabled pools fall back to passive health only.                    |
| `path`                 | string                        | `"/healthz"`       | Probe path. Always GET unless overridden.                           |
| `method`               | string                        | `"GET"`            |                                                                     |
| `interval_ms`          | u64                           | `10000`            | Time between probes per member.                                     |
| `timeout_ms`           | u64                           | `2000`             | Per-probe.                                                          |
| `healthy_threshold`    | u32                           | `2`                | Consecutive successes to mark healthy.                              |
| `unhealthy_threshold`  | u32                           | `3`                | Consecutive failures to mark unhealthy.                             |
| `expected_status`      | integer or `"start-end"` range| `200`              | Anything outside the matcher counts as a probe failure.             |
| `initial_state`        | `"healthy"` \| `"unhealthy"`  | `"unhealthy"`      | Pessimistic by default: wait for probes before routing.             |

### `[upstreams.drain]`

| Field        | Default | Notes                                                                       |
|--------------|---------|-----------------------------------------------------------------------------|
| `timeout_ms` | `60000` | Used when a member is removed via the admin API. After this, force-drain.  |

### `[upstreams.pool]`

Per-pool tuning of the hyper client's idle connection pool. See
[hardening.md](hardening.md#upstream-connection-pool).

| Field               | Default  | Notes                                                       |
|---------------------|----------|-------------------------------------------------------------|
| `idle_timeout_ms`   | `60_000` | How long an idle pooled connection is kept before recycling. |
| `max_idle_per_host` | `100`    | Max idle connections retained per backend host.             |

## `[[routes]]`

```toml
[[routes]]
hosts          = ["api.example.com", "*.api.internal"]
methods        = ["GET", "POST"]
path_prefix    = "/api/v1"
strip_prefix   = "/api/v1"
timeout_ms     = 5000
max_body_bytes = 1_048_576
auth           = "main"
upstream       = "api"
```

### Matchers

| Field         | Type             | Notes                                                                  |
|---------------|------------------|------------------------------------------------------------------------|
| `hosts`       | array of strings | Any matches. `*.example.com` matches subdomains, not the apex.         |
| `host`        | string           | Singular alias.                                                        |
| `methods`     | array of strings | Any matches. Empty = any method.                                       |
| `method`      | string           | Singular alias.                                                        |
| `path_exact`  | string           | Exact path. Mutually exclusive with `path_prefix`. Beats every prefix. |
| `path_prefix` | string           | Segment-aware. `/api` matches `/api/x`, never `/apifoo`. Default `/`.  |

Most-specific match wins. Exact > prefix; longer prefix > shorter prefix.
Ties broken by config order.

### Modules

| Field            | Type    | What it does                                                          |
|------------------|---------|-----------------------------------------------------------------------|
| `strip_prefix`   | string  | Remove from the path before forwarding upstream.                      |
| `timeout_ms`     | u64     | Upper bound on upstream response time. 504 on expiry.                 |
| `max_body_bytes` | u64     | Cap inbound body via Content-Length pre-check. 413 if exceeded.       |
| `auth`           | string  | Name of an `[[auth]]` block.                                          |
| `preserve_host`  | bool    | Forward the client's `Host` to the upstream unchanged instead of rewriting it to the member's address. Like nginx `proxy_set_header Host $http_host` / Apache `ProxyPreserveHost On`. Needed by backends that check Host/Origin (e.g. Grafana). Default `false`. Applies to HTTP/1.1 upstreams; HTTP/2 derives `:authority` from the member address. |

### Required

| Field      | Type    | Notes                                       |
|------------|---------|---------------------------------------------|
| `upstream` | string  | Name of an `[[upstreams]]` pool.            |

## `[[auth]]`

JWT auth block. Referenced from routes via `auth = "<name>"`.

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

| Field             | Type             | Default                        | Notes                                                                           |
|-------------------|------------------|--------------------------------|---------------------------------------------------------------------------------|
| `name`            | string           | required                       | Referenced from routes.                                                         |
| `jwks_url`        | URL              | required                       | Fetched once at startup, refreshed on `kid` miss.                               |
| `issuer`          | string           | unset                          | When set, enforces `iss` claim equality.                                        |
| `audience`        | string           | unset                          | When set, enforces `aud` claim membership.                                      |
| `algorithms`      | array of strings | `["RS256", "ES256", "EdDSA"]`  | Whitelist. Other algs in the token → 401.                                       |
| `required_claims` | array of strings | `[]`                           | Claim names that must be present.                                               |
| `inject_headers`  | array of mapping | `[]`                           | See below.                                                                      |

### `inject_headers` mapping

| Field      | Type    | Default | Notes                                                                        |
|------------|---------|---------|------------------------------------------------------------------------------|
| `claim`    | string  | required| Top-level claim in the JWT payload.                                          |
| `header`   | string  | required| Header to set on the upstream-bound request.                                 |
| `required` | bool    | `false` | When `true`, absent claim → 403. When `false`, header is dropped silently.   |

Each mapped header is **reserved**: an inbound request that sets one of them
is rejected with 403 (`outcome="spoofed_header"`), even if the matching
claim is absent. This catches spoofing attempts and accidental
upstream-of-upstream forwarding.

Value coercion when injecting:

| Claim shape       | Header value                       |
|-------------------|------------------------------------|
| string            | as-is                              |
| number / bool     | stringified                        |
| array of strings  | comma-joined                       |
| array mixed / object | JSON-encoded                    |
| null / missing (and not required) | header dropped     |

## `[egress]`

The forward proxy listener. Absent = not started.

```toml
[egress]
bind           = "0.0.0.0:3128"
default_action = "deny"
sni_enforce    = false

[egress.auth]                     # optional
mode  = "basic_log_only"
realm = "egress"

[[egress.rules]]
action = "allow"
hosts  = ["*.github.com"]

[[egress.rules]]
action = "allow"
cidrs  = ["10.0.0.0/8"]

[[egress.rules]]
action = "deny"
cidrs  = ["169.254.0.0/16"]
```

| Field            | Type                    | Default  | Notes                                                                         |
|------------------|-------------------------|----------|-------------------------------------------------------------------------------|
| `bind`           | socket                  | required |                                                                               |
| `default_action` | `"allow"` \| `"deny"`   | `"deny"` | When no rule matches.                                                         |
| `sni_enforce`    | bool                    | `false`  | When true, SNI ≠ CONNECT target aborts. When false, mismatch is logged WARN.  |

### `[egress.auth]`

```toml
mode  = "basic_log_only"
realm = "homelab egress"
```

```toml
mode             = "jwt"
block            = "main"           # name of an [[auth]] block
originator_claim = "sub"            # default
```

| Mode             | What it does                                                              |
|------------------|---------------------------------------------------------------------------|
| `basic_log_only` | Extract `Proxy-Authorization` username, log it, don't validate password.  |
| `jwt`            | Validate a Bearer token against a named `[[auth]]` block.                 |

### `[[egress.rules]]`

| Field    | Type                          | Notes                                                  |
|----------|-------------------------------|--------------------------------------------------------|
| `action` | `"allow"` \| `"deny"`         | Required.                                              |
| `hosts`  | array of host patterns        | Exact or `*.domain` wildcard. Default empty.           |
| `cidrs`  | array of CIDRs                | IPv4 or IPv6. Default empty.                           |

A rule matches if **any** of its hosts **or any** of its cidrs hits the
target. First match wins. Hostname targets are also resolved via DNS so
CIDR-based denies catch DNS-aliased bypasses.

## `[nats]`

Optional NATS-backed service registration. **Only acted upon in a build with
`--features nats`** - a config that uses `[nats]`/`[upstreams.nats]` on a default
binary fails boot loudly. See [service-registration.md](service-registration.md).

```toml
[nats]
url        = "tls://nats:4222"
bucket     = "quik_registrations"
creds_file = "/etc/quik/quik.creds"
```

| Field            | Default | Notes                                                        |
|------------------|---------|--------------------------------------------------------------|
| `url`            | -       | Required. `nats://…` or `tls://…`.                           |
| `bucket`         | -       | Required. JetStream KV bucket holding registrations.         |
| `creds_file`     | none    | Path to a decentralised-JWT `.creds` file. Omit for no-auth (local only). |
| `reconnect_secs` | `5`     | Pause between reconnect attempts while NATS is unreachable.   |

When NATS is down (at boot or later) the proxy serves last-known / static-config
membership and keeps retrying - it never fails on the NATS dependency, and a
disconnect never flushes members.

### `[upstreams.nats]`

Per-pool binding that makes a pool NATS-backed. A pool with this block may start
with no static `members`.

```toml
[[upstreams]]
name = "checkout"

[upstreams.nats]
subject                    = "reg.shop.checkout.>"
allow_addresses            = ["10.0.0.0/8", ".svc.cluster.local"]
max_members                = 500
max_instances_per_service  = 50
```

| Field                       | Default | Notes                                                            |
|-----------------------------|---------|------------------------------------------------------------------|
| `subject`                   | -       | Required. KV subject subtree feeding this pool, e.g. `reg.shop.checkout.>`. Must end with a wildcard (`>`/`*`) **and** have a literal prefix before it (a bare `>` is rejected - it matches nothing). |
| `allow_addresses`           | -       | **Required, non-empty.** CIDR (`10.0.0.0/8`), bare IP, or host-suffix (`.svc.local`). A self-asserted address outside this set is rejected. Fails *safe*. **Prefer CIDRs** - a host-suffix admits a hostname and trusts DNS to resolve it (see the design doc's DNS-trust residual). |
| `max_members`               | none    | Backstop cap on total pool members. Size **well above** the real fleet - a tight cap fails *unsafe* (locks out scale-up). |
| `max_instances_per_service` | none    | Cap per `reg.<ns>.<service>.*` (the surgical control). |

The operator-override subtree (`override.<…>`, derived from `subject`) is watched
automatically: an `override` key drains/suppresses the matching member
(operator-wins, durable across restart).
