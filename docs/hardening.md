# Hardening

Default config is appropriate for a proxy behind a trusted load balancer or
CDN, where most adversarial traffic never reaches quik. This page covers the
knobs you'll want to think about before exposing a quik instance directly
to the public internet, plus the things quik does **not** defend against —
where the right answer is a CDN, a WAF, or kernel/network-layer controls
upstream of the process.

The relevant config sections are [`[listener.limits]`](#listener-limits)
and [`[upstreams.<pool>.pool]`](#upstream-connection-pool).

## Threat model

quik is a small, single-binary HTTP reverse proxy. It can meaningfully
defend against:

- **Slow-client resource exhaustion** — slowloris and similar attacks that
  open a connection and then dribble bytes to tie up server time.
- **HTTP/2 abuse** — clients that open many concurrent streams,
  rapid-reset (CVE-2023-44487), or hold connections open without sending
  PING responses.
- **Stalled WebSockets** — long-lived tunnels with no application
  keepalive, or tunnels that need to be cleared during a proxy restart.
- **Upstream resource leakage** — idle pooled connections to backends
  building up forever.

quik **cannot** meaningfully defend against:

- **Volumetric L3/L4 floods** (UDP amplification, SYN floods large enough
  to saturate the link) — by the time traffic reaches the proxy, the pipe
  is already saturated. This is what CDNs and anycast scrubbing networks
  buy.
- **Application-layer business-logic abuse** — `POST /expensive-endpoint`
  100 times. quik can rate-limit by IP (when rate limiting ships) but the
  authoritative quota lives in the application; see the rate-limiting
  scope discussion in [admin-api.md](admin-api.md).
- **Body inspection / WAF rules** — quik does not parse or filter request
  bodies beyond size limits. If you need pattern matching against payloads,
  put a dedicated WAF ([Coraza](https://coraza.io/), ModSecurity) in front.

The rest of this page is the bounded set of L7 defences quik does offer.

## Listener limits

```toml
[listener.limits]
header_read_timeout_ms             = 30_000      # slowloris
http2_keep_alive_interval_ms       = 0           # disabled by default
http2_keep_alive_timeout_ms        = 20_000
http2_max_concurrent_streams       = 256
http2_max_concurrent_reset_streams = 64          # CVE-2023-44487
websocket_idle_timeout_ms          = 300_000     # 5 min
```

### `header_read_timeout_ms`

How long the proxy waits to receive the complete HTTP/1.1 request headers
before closing the connection. Mitigates **slowloris**: an attacker opens
a connection and sends one header byte every few seconds, holding the
listener slot indefinitely.

| Deployment              | Recommended         |
|-------------------------|---------------------|
| Behind a CDN            | 30_000 (default) — CDN handles the abuse |
| Direct to public        | 5_000–10_000        |
| LAN / homelab           | 30_000 or disable (`0`) |

Disable with `0`. Doing so also removes a hyper-side defence that fires on
genuinely-broken clients; only do it if you've verified the throughput
won't suffer.

### `http2_keep_alive_interval_ms` / `http2_keep_alive_timeout_ms`

Sends a PING frame every `interval_ms` on otherwise idle HTTP/2
connections. If the peer doesn't respond within `timeout_ms`, the
connection is dropped. Two reasons to enable:

1. **NAT timeouts.** Long-lived gRPC / streaming connections behind a NAT
   that times out idle flows after 60–90 seconds will silently break;
   PINGs keep the flow alive *and* detect when the peer has actually died.
2. **Dead-peer detection.** A client that crashed without sending TCP FIN
   leaves a half-open connection that consumes a server slot until the
   kernel TCP keepalive (typically 2 hours) reaps it.

Disabled by default (`interval_ms = 0`) — appropriate when long-lived h2
isn't in your traffic profile. Enable with `interval_ms = 30_000` and
`timeout_ms = 20_000` for gRPC-streaming workloads.

### `http2_max_concurrent_streams`

Maximum HTTP/2 streams a single inbound connection may have open at once.
This bounds the memory and task count one client can pin. Hyper's default
is unbounded; quik's default is `256`, which is generous for legitimate
clients (browsers cap themselves around 100) but rules out the
pathological case of a single client opening 100k streams.

Lower it (e.g. `64`) when traffic is direct from untrusted clients;
raise it (e.g. `1024`) for trusted backend-to-backend traffic where
many concurrent requests over one connection is the actual workload.

### `http2_max_concurrent_reset_streams`

Limits the number of locally-reset streams the server tracks in memory
(RFC 9113 §5.1.2). Default `64`. The 2023 "Rapid Reset" attack
(CVE-2023-44487) opens a stream and immediately RSTs it — at high rates,
this can starve the server even though no stream is "active". Hyper
caps this automatically; this knob makes the cap configurable for
defenders who want to tighten it further.

> **Note.** This option is currently parsed but not yet plumbed through
> to hyper's builder — the underlying API stabilised after the rest of
> these landed. Tracked as a follow-up.

### `websocket_idle_timeout_ms`

A WebSocket tunnel established through quik holds two open sockets and
runs forever by default. This timeout culls tunnels with no bytes in
either direction for the configured period.

| Deployment                  | Recommended      |
|-----------------------------|------------------|
| Chat / control-plane WS     | 300_000 (default) — application sends pings|
| Long-poll-style replacement | 600_000–900_000  |
| Direct, no app-level pings  | 60_000–120_000   |
| Strict resource isolation   | 30_000           |

Disable with `0`. Most WS application protocols (Socket.IO, GraphQL
subscriptions, MQTT-over-WS) send their own pings on a 30–60 s cadence
— the default 5 min idle is comfortably longer than any legitimate one.

## Upstream connection pool

```toml
[[upstreams]]
name = "api"
# ...

[upstreams.pool]
idle_timeout_ms   = 60_000    # close idle pooled conns after this long
max_idle_per_host = 100       # max idle connections kept per backend host
```

These tune the hyper client's connection-reuse pool for the proxy→backend
hop. Defaults match the historical hardcoded values. Tighten on
memory-constrained hosts; loosen for very hot pools that benefit from
keeping more warm connections around.

`idle_timeout_ms` is also a defence against subtle backend bugs — some
servers happily hold idle connections for hours but then 500 on the first
request after that. Forcing the pool to recycle puts a ceiling on
backend-bug staleness.

## WebSocket drain semantics

When the proxy receives `SIGTERM` (or first `SIGINT`):

1. The listener stops accepting new connections.
2. `/healthz` returns 503.
3. In-flight HTTP requests get up to `shutdown.drain_grace_seconds` to
   complete.
4. **Open WebSocket tunnels are closed.** Each spawned bidirectional copy
   task races against the drain signal; when drain fires, the tunnel is
   dropped and the client sees a TCP FIN.

This is intentional — long-lived WS connections established before the
rollover would otherwise pin the old proxy indefinitely. The expected
client behaviour is "reconnect", which routes the new connection to the
already-spun-up replacement proxy.

If your client doesn't auto-reconnect, configure the load balancer to
keep the old proxy in the pool until WS tunnels naturally close, instead
of relying on this drain hook.

## What's not implemented yet

These are L7 hardening axes worth adding next; tracked for a future
hardening pass.

| Gap                                                              | Note                                              |
|------------------------------------------------------------------|---------------------------------------------------|
| Inbound body idle timeout (slow-POST mitigation)                 | Needs a polled-body wrapper                       |
| Connection limit per inbound IP                                  | Would also gate the slowloris path                |
| Rate limiting (per-IP, per-route, per-sub)                       | See the rate-limit ADR for design                 |
| `http2_max_concurrent_reset_streams` plumbing                    | Config parsed, not yet applied to hyper builder   |

Until those land, the recommended posture for direct-to-public deployments
is a CDN (Cloudflare / Fastly / CloudFront) in front of quik. The CDN
handles volumetric / L3 / L4 attacks, rate limits, and WAF rules; quik
does the L7 routing, TLS termination, auth, and load-balancing.

## Tightened example: direct-to-public

A config block to start from when there's no CDN ahead of quik:

```toml
[listener.limits]
header_read_timeout_ms             = 5_000
http2_keep_alive_interval_ms       = 30_000
http2_keep_alive_timeout_ms        = 10_000
http2_max_concurrent_streams       = 64
http2_max_concurrent_reset_streams = 16
websocket_idle_timeout_ms          = 60_000

[shutdown]
drain_grace_seconds = 30

[admin]
bind = "127.0.0.1:9090"   # never expose the admin listener publicly

[admin.auth.write]
mode      = "bearer_token"
token_env = "QUIK_ADMIN_TOKEN"
```

For the loopback bind on `[admin]`: even on a single-host deployment, the
admin listener should not be public — it carries pool mutation endpoints
and metrics that reveal infrastructure shape. Bind to `127.0.0.1` and
reach it via an SSH tunnel or a local control script.
