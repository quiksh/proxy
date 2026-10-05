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

> **Reloadable at runtime.** `[[routes]]`, `[[auth]]`, `[[authorizers]]` and `[forwarded]` can be
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
| `tls.cert_path`   | path     | yes¹     | PEM cert (chain).                           |
| `tls.key_path`    | path     | yes¹     | PEM private key.                            |
| `tls.self_signed` | bool     | no       | Generate an ephemeral self-signed cert at boot instead. See below. |
| `limits`          | table    | no       | See [`[listener.limits]`](#listenerlimits). |

¹ Set both `cert_path` and `key_path`, or `self_signed = true` - not both.

ALPN advertises `h2` and `http/1.1`.

**Behind a load balancer.** An AWS ALB (HTTPS target group) or NLB (TLS
target group) re-encrypts to its targets without verifying their certificate.
There, `self_signed = true` gives quik a fresh in-memory P-256 key and
`localhost` certificate on every boot - no key file in the image, nothing to
rotate. Never use it on a listener that clients reach directly: they'd get a
certificate error, or learn to click through one.

```toml
[listener]
bind = "0.0.0.0:8443"

[listener.tls]
self_signed = true
```

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
| `authorizer`     | string  | Name of an `[[authorizers]]` block. Runs after `auth` when both are set. |
| `require`        | table   | Extra claim rules and step-up for this route, on top of `auth`. See [`[routes.require]`](#routesrequire). |
| `preserve_host`  | bool    | Forward the client's `Host` to the upstream unchanged instead of rewriting it to the member's address. Like nginx `proxy_set_header Host $http_host` / Apache `ProxyPreserveHost On`. Needed by backends that check Host/Origin (e.g. Grafana). Default `false`. Applies to HTTP/1.1 upstreams; HTTP/2 derives `:authority` from the member address. |

### Required

| Field      | Type    | Notes                                       |
|------------|---------|---------------------------------------------|
| `upstream` | string  | Name of an `[[upstreams]]` pool.            |

### `[routes.require]`

What this route needs beyond its `auth` block. The block says how to verify a
token and what every token from that issuer must satisfy; `require` says what
*this* route asks on top, so one block can serve routes with different needs.
Requires `auth`. Unknown keys are rejected, so a typo can't silently drop a
requirement.

```toml
[[routes]]
hosts = ["admin-api.corp.example.test"]
auth  = "corp"
upstream = "admin-api"

[routes.require]
claim_contains       = { groups = "admin-api-users" }
amr                  = ["hwk"]     # RFC 8176 method: hardware key
max_auth_age_seconds = 43200       # authenticated within 12 hours
```

| Field                  | Type             | Failure | Notes |
|------------------------|------------------|---------|-------|
| `claim_equals`         | table            | 403     | As on `[[auth]]`, for this route only. |
| `claim_contains`       | table            | 403     | As on `[[auth]]`, for this route only. |
| `amr`                  | array of strings | step-up | Each value must be in the token's `amr` array. |
| `max_auth_age_seconds` | u64              | step-up | The token's `auth_time` must be at most this old. Missing → fails. 60 s of future skew allowed. |

Checks run in order: the block's claim rules, the route's claim rules, then
`amr` and `max_auth_age_seconds`. Claim rules come first so nobody is asked to
touch a hardware key for a route they can't use.

**Step-up** means:

- **Page loads** (with the block's `login_redirect` set) get a 302 to the
  login URL with the route's requirements appended: `amr_values=<space-separated
  amr>` and `max_age=<seconds>`, like the authorisation request parameters in
  [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470). The same parameters are
  added to *every* login redirect from a route with `amr` or
  `max_auth_age_seconds`, including first sign-in. The sign-in service can
  then satisfy everything in one round trip.
- **Everything else** gets a 401 with
  `WWW-Authenticate: Bearer error="insufficient_user_authentication"`, plus
  `amr_values="…"` and `max_age=…` when set. A single-page app can tell
  "step up" apart from "not signed in" this way.

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
| `claim_equals`    | table            | `{}`                           | Claim → required string / integer / bool, for every use of the block. Mismatch or absent → 403. [Details](#claim-rules). |
| `claim_contains`  | table            | `{}`                           | Claim → value an array claim must contain (or a string claim must have as a space-separated token). → 403. |
| `token_cookie`    | string           | unset                          | Read the token from this cookie instead of `Authorization`. [Details](#browser-sessions). Routes only. |
| `forward_token_cookie` | bool        | `false`                        | Forward the session cookie on this block's routes. By default it is removed from `Cookie` on every route. |
| `login_redirect`  | URL template     | unset                          | Where browsers are sent to sign in; `{url}` is the encoded original URL. Routes only. |

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

### Claim rules

`claim_equals` and `claim_contains` on a block are what **every** token from
that issuer must satisfy wherever the block is used, including
`[egress.auth]`. A typical example is the organisation's domain. Rules for a
single route go in [`[routes.require]`](#routesrequire), which also holds
step-up.

```toml
[[auth]]
name           = "corp"
# ...jwks_url / issuer / audience...
claim_equals   = { hd = "example.test", email_verified = true }
```

- `claim_equals` compares by type: `true` does not match the string `"true"`,
  and `2` does not match `"2"`.
- `claim_contains` on an array (`groups = ["a", "b"]`) matches an element; on a
  string (`scope = "read write"`) it matches a whole space-separated token, so
  `write` matches but `writ` does not.
- Failure is a 403, never a login redirect: a fresh token from the same
  issuer wouldn't change the answer.

### Browser sessions

`token_cookie` and `login_redirect` turn an `[[auth]]` block into the
enforcement half of an identity-aware proxy: a separate sign-in service issues
a session JWT in a cookie, and quik checks it on every request. See
[identity-aware proxy](identity-aware-proxy.md) for the full contract.

```toml
[[auth]]
name           = "corp"
jwks_url       = "https://auth.corp.example.test/.well-known/jwks.json"
issuer         = "https://auth.corp.example.test"
audience       = "corp"
algorithms     = ["ES256"]
token_cookie   = "__Secure-corp_session"
login_redirect = "https://auth.corp.example.test/login?rd={url}"
claim_equals   = { hd = "example.test" }
inject_headers = [{ claim = "email", header = "x-auth-email", required = true }]
```

- **Token source.** With `token_cookie` set, *only* that cookie is read. A
  bearer token in `Authorization` is ignored for authentication and forwarded
  upstream unchanged, so an app's own token can travel alongside the session.
- **Cookie stripping.** Every `token_cookie` in the config is removed from
  `Cookie` on **every** route before forwarding, including routes without
  `auth` or with a different block. The browser sends the cookie to every path
  on the host, so otherwise any upstream there could capture and replay the
  session. Other cookies are kept byte for byte. The one exception is a route
  whose own block sets `forward_token_cookie = true`.
- **Login redirect.** When signing in again could help - no token, a malformed,
  expired or unverifiable one, or a failed `[routes.require]` step-up check - a **page load** gets
  `302 Found` to `login_redirect` with `Cache-Control: no-store`. A page load
  is a GET/HEAD with `Sec-Fetch-Mode: navigate` or, from clients that don't
  send fetch metadata, `Accept: text/html`. Everything else (`fetch`, XHR,
  scripts, POSTs) gets the 401/403 it would without a redirect.
- **`{url}`** becomes the percent-encoded `https://<host><path>?<query>` of the
  original request, before `strip_prefix`. Step-up parameters are appended to
  the query (see [`[routes.require]`](#routesrequire)), so the template must
  not contain a fragment (`#`). The host comes from the client, so
  **the sign-in service must check the return URL against its own allow-list**
  before redirecting back to it.
- Without `login_redirect`, a missing session is a 401 and an expired one a
  403, as for bearer tokens.

Metrics: `quik_auth_total{auth,outcome}` gains `claim_mismatch` and
`insufficient_auth` outcomes (expired tokens stay under `bad_claims`), and
`quik_auth_redirects_total{auth}` counts login redirects.

## `[[authorizers]]`

An external HTTP authoriser, consulted on every request to a route with
`authorizer = "<name>"`. Use it where you would use an AWS API Gateway Lambda
authoriser, but with a long-running internal service on warm keep-alive
connections, so there are no cold starts.

```toml
[[authorizers]]
name            = "internal"
url             = "https://authz.internal:8443/v1/authorize"
timeout_ms      = 200
forward_headers = ["authorization", "x-api-key"]
inject_headers  = ["x-user-id", "x-tenant-id", "x-scopes"]
on_error        = "deny"
tls             = { ca_path = "/etc/quik/internal-ca.pem" }

[[routes]]
path_prefix = "/api"
auth        = "main"       # optional: JWT is checked first, locally
authorizer  = "internal"   # then the authoriser, which also gets the claims
upstream    = "api"
```

| Field             | Type             | Default  | Notes                                                                 |
|-------------------|------------------|----------|-----------------------------------------------------------------------|
| `name`            | string           | required | Referenced from routes.                                               |
| `url`             | URL              | required | `http://` or `https://`. Receives a `POST` per request.               |
| `timeout_ms`      | u64              | `1000`   | Covers the whole call. If it expires, quik treats it as an authoriser error. |
| `forward_headers` | array of strings | `[]`     | Inbound headers copied into the request quik sends. No headers are sent unless listed here. |
| `inject_headers`  | array of strings | `[]`     | Headers the authoriser may set upstream. Each one is also **reserved** (see below). |
| `include_body`    | bool             | `false`  | Read the whole request body into memory and send it in `body`. Without it, request bodies are forwarded as they arrive, without being held in memory. |
| `max_body_bytes`  | u64              | `65536`  | Largest body accepted when `include_body` is on; bigger bodies get 413. Can't exceed 1 MiB. If the route's own `max_body_bytes` is lower, that limit applies. |
| `body_timeout_ms` | u64              | `10000`  | With `include_body`, the time a client has to finish sending its body. A body still arriving after this gets 408. |
| `on_error`        | `deny` \| `allow` | `deny`   | What happens when the authoriser gives no answer. `deny` returns 503; `allow` forwards the request without injected headers. |
| `tls.ca_path`     | path             | unset    | Extra PEM CA bundle to trust, on top of the public roots.             |
| `tls.cert_path` / `tls.key_path` | path | unset | Client certificate and key for mTLS to the authoriser. Set both or neither. |

### The request quik sends

`POST <url>` with `content-type: application/json`:

```json
{
  "version": "1",
  "request_id": "6f1c…",
  "route": "* */api",
  "source_ip": "203.0.113.7",
  "method": "POST",
  "host": "api.example.com",
  "path": "/api/orders",
  "query": "limit=5",
  "headers": { "authorization": "Bearer …" },
  "claims": { "sub": "user-42", "tenant_id": "t_1" }
}
```

- `route` is quik's label for the route that matched: `<host> <method> <path>`, with `*` meaning any. It's the same label that appears in the access log.
- `path` is the path the client sent, before any `strip_prefix`.
- `query` is `null` when the request has no query string.
- `headers` only contains the names listed in `forward_headers`, in lower case. When a header appears more than once, its values are joined with `, `.
- `claims` is only present when the route also has an `auth` block. It holds the verified JWT claims.
- `body` and `is_base64_encoded` are only present with `include_body`. A UTF-8 text body is sent as is (e.g. a JSON string you can parse again). Anything else, including UTF-8 containing control characters other than tab, LF and CR, is base64-encoded and `is_base64_encoded` is `true`. That keeps the request to the authoriser at most about 4/3 of `max_body_bytes`. An empty body is `""`. This matches API Gateway's `body` / `isBase64Encoded`.
- `source_ip` is the immediate peer. Behind a load balancer, forward `x-forwarded-for`, but only rely on it from peers listed in `trusted_proxies`.

### Response contract

The authoriser's HTTP status is the decision.

| Authoriser response | quik does |
|---|---|
| **2xx**, empty body (e.g. `204`) | Allows the request. |
| **2xx**, JSON body `{"headers": {"x-user-id": "u_1"}}` | Allows the request and sets those headers on the upstream request. Names not in `inject_headers` are dropped with a warning. A value that isn't a valid header string counts as an error. |
| **4xx** | Denies the request. The status and body are sent to the client, plus `content-type` and `www-authenticate` if set. Other response headers are dropped. |
| **Anything else** (3xx, 5xx, timeout, connection error, a 2xx body that isn't JSON) | Counts as an error and is handled by `on_error`. Redirects aren't followed. |

Response bodies are capped at 64 KiB. A larger allow body counts as an error; a larger deny body is dropped and the status is still sent.

### Reserved and forbidden headers

Every `inject_headers` name is **reserved**. If an inbound request already
carries one (in any letter case), quik rejects it with 403
(`outcome="spoofed_header"`) without calling the authoriser.

Some headers can't be listed in `inject_headers` because quik controls them:
hop-by-hop headers, `host`, `content-length`, `content-type`,
`content-encoding`, `authorization`, `cookie`, every `x-forwarded-*` header,
`x-real-ip`, `forwarded`,
`x-request-id`/`request-id` and `traceparent`. A route can't use an `auth`
block and an authoriser that inject the same header; config validation
rejects the overlap.

### Metrics

| Metric                              | Type      | Labels                    |
|-------------------------------------|-----------|---------------------------|
| `quik_authorizer_total`             | counter   | `authorizer`, `outcome` (`allow`, `deny`, `error_denied`, `error_allowed`, `spoofed_header`) |
| `quik_authorizer_duration_seconds`  | histogram | `authorizer`              |

WebSocket upgrades go through `auth` and the authoriser in the same way as other requests.

### Caching decisions (`[authorizers.cache]`)

Each quik instance can cache the authoriser's decisions in memory, so repeat
requests skip the network call. It's off by default.

```toml
[[authorizers]]
name = "internal"
url  = "https://authz.internal/v1/authorize"
forward_headers = ["authorization"]
inject_headers  = ["x-user-id", "x-tenant-id"]

[authorizers.cache]
ttl_seconds = 300                      # 0–900 (15 minutes); 0 = off
key         = ["header:authorization"] # optional; see below
max_entries = 100000
```

| Field          | Type             | Default    | Notes |
|----------------|------------------|------------|-------|
| `ttl_seconds`  | u64              | `0`        | How long a decision stays cached, 0–900 seconds. 0 turns caching off. |
| `key`          | array of strings | whole request | What counts as "the same request". See below. |
| `max_entries`  | usize            | `100000`   | Upper limit per quik instance. When full, entries closest to expiry are removed first. Plan for about 0.5 KB per entry with three injected headers. |
| `cache_denies` | bool             | `true`     | Also cache 4xx denies, which protects the authoriser from repeated bad credentials. |
| `backend`      | `memory`         | `memory`   | Where decisions are stored. Only in-process memory is available today. |

**What's cached.** 2xx allows, including their injected headers, and 4xx
denies, including the body that's passed to the client. Authoriser errors
(timeouts, 5xx) are never cached. The authoriser can control caching per
response with `Cache-Control`: `no-store`, `no-cache`, `private` or
`max-age=0` stop that response being cached, and `max-age=N` caches it for
at most N seconds, never longer than `ttl_seconds`.

**The key.** When `key` isn't set, quik keys on everything the authoriser
receives except `request_id`: method, host, path, query, source IP, the
`forward_headers` and the JWT claims. A cached decision is therefore only
reused for a request that's identical from the authoriser's point of view.
This is the safe default.

To cache by identity alone, list only the fields that decide the outcome,
for example `["header:authorization"]`, like API Gateway's identity-source
caching. This gives far better hit rates, but the authoriser's decision must
then be the same for every path and method that credential can reach. If
admin routes need a different decision, either give them their own
authoriser block or add `"path"` to the key. Valid entries: `method`, `host`,
`path`, `query`, `source_ip`, `claims`, `header:<name>`.

**Security.**
- The spoofed-header check runs on every request, cached or not.
- Only a SHA-256 hash of the key is stored, never the token itself.
- A config reload clears the cache.
- A revoked credential can keep working for up to `ttl_seconds`. Choose the
  TTL with that in mind, or have the authoriser send a shorter `max-age` for
  sensitive principals.
- Caching can't be combined with `include_body`, because the decision depends
  on the payload.

**Metrics.** `quik_authorizer_cache_total{authorizer,result}`, where
`result` is `hit`, `miss` or `evicted`.

#### Caching across several quik instances

Each quik instance has its own cache. With N instances behind a load balancer
that spreads requests evenly, a user's requests reach every instance, so in
the worst case the authoriser is called once **per user, per instance, per
TTL**:

```
authoriser calls/s ≤ active users × N ÷ ttl_seconds   (and never more than the uncached request rate)
```

For example, 1M users who are all active within a 5-minute window, with 4
instances and `ttl_seconds = 300`, means at most about 13k calls/s, and each
instance holds up to 1M entries (about 520 MB). How to reduce that:

- **Narrow the key to the caller's identity** (`["header:authorization"]` or
  `["claims"]`). With the default key, every distinct path or query is a
  separate entry, so ID-heavy URLs (`/orders/123`) rarely hit the cache.
- **Route each caller to the same instance.** Configure the load balancer to
  hash on `Authorization` or the session cookie. Each instance then sees about
  1/N of the users, so its cache holds 1/N of the entries and the authoriser
  load drops by about N times.
- **Size `max_entries` to the number of users active in a TTL window on one
  instance**, not the total user count. Once the cache is full, the entries
  closest to expiry are dropped; the rest still give hits.
- **If the credential is a JWT, verify it locally with `[[auth]]`** and leave
  only policy decisions to the authoriser. Checking a signature needs no
  network call at all.
- **Cache inside the authoriser too.** A cache miss in quik then costs one
  fast round trip rather than a full policy evaluation.

A shared cache across instances (NATS KV or Redis) isn't available yet. The
storage interface is designed so one can be added as another `backend`.

### Request bodies (`include_body`)

To decide based on the payload (amounts, resource IDs, GraphQL operation
names and so on), set `include_body = true`. quik then handles the request
like this:

1. Checks the JWT, if `auth` is set. A request without a valid token is
   rejected before its body is read.
2. Rejects with 413 if the declared `Content-Length` is over the cap. A body
   sent without a length (chunked) gets 413 as soon as it goes over the cap.
3. Calls the authoriser with the body included.
4. On allow, forwards **the same bytes** to the upstream.

If the body hasn't fully arrived within `body_timeout_ms`, the client gets
408, so a slow sender can't hold a buffer open.

Request **trailers are dropped** on these routes, because the body is
forwarded as a single block. Don't use `include_body` on routes that rely on
trailers, such as gRPC.

Only routes whose authoriser uses `include_body` hold request bodies in
memory. Each in-flight request on those routes uses up to `max_body_bytes`,
so keep the limit low. That's why it's capped at 1 MiB.

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
