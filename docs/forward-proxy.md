# Forward (egress) proxy

quik can run a second listener that accepts HTTP `CONNECT` requests and
tunnels them to allowed destinations. It's the same binary as the reverse
proxy - just opt into the `[egress]` block in your config and it spins up
another listener alongside the main one.

The use case: you want outbound HTTPS from a network to go through a
chokepoint where you can:

- restrict which destinations are reachable (allow-list by host or CIDR),
- audit who initiated each request (Basic auth username or JWT subject), and
- catch obvious bypasses (DNS-rebinding, SNI spoofing).

It is **not** an HTTPS interception proxy. quik never sees the bytes inside
the tunnel - TLS stays end-to-end between the client and the destination.
What it does see is the CONNECT target (host:port) and, optionally, the
SNI extension in the first TLS frame.

## Minimal config

```toml
[egress]
bind           = "0.0.0.0:3128"
default_action = "deny"
sni_enforce    = false

[[egress.rules]]
action = "allow"
hosts  = ["*.github.com", "github.com"]

[[egress.rules]]
action = "allow"
cidrs  = ["10.0.0.0/8", "192.168.0.0/16"]
```

Set `https_proxy=http://your-proxy:3128` on a client and outbound HTTPS to
GitHub or RFC1918 addresses is allowed; everything else is denied.

## How rules are evaluated

The rule list is **first-match-wins**. Each rule has an action and a set of
hosts and/or CIDRs:

- A rule matches if the CONNECT target hits **any** of its `hosts` **or**
  any of its `cidrs`.
- Host patterns can be exact (`api.example.com`) or wildcard subdomain
  (`*.example.com`, which matches `api.example.com` but not the apex
  `example.com`).
- CIDRs can be IPv4 or IPv6 (`10.0.0.0/8`, `fe80::/10`).
- Hostname targets are also resolved via DNS and the resulting addresses
  are checked against `cidrs`. That means a `deny` rule on
  `169.254.0.0/16` blocks a metadata-service bypass attempted via DNS too.

If no rule matches, `default_action` applies. `deny` is the recommended
default; `allow` only makes sense if you're using rules purely as a deny
list.

A practical layout:

```toml
[egress]
bind           = "0.0.0.0:3128"
default_action = "deny"

# Explicitly deny dangerous destinations first.
[[egress.rules]]
action = "deny"
cidrs  = [
    "169.254.0.0/16",   # link-local incl. cloud metadata services
    "fe80::/10",        # IPv6 link-local
    "127.0.0.0/8",      # loopback
]

# Then allow the destinations you actually need.
[[egress.rules]]
action = "allow"
hosts  = ["*.github.com", "github.com", "registry-1.docker.io"]

[[egress.rules]]
action = "allow"
cidrs  = ["10.0.0.0/8"]   # internal services
```

Anything not matched falls to `default_action = deny`.

## SNI verification

When a client tunnels HTTPS through CONNECT, the first thing they send
inside the tunnel is the TLS ClientHello - which carries the destination
hostname in the SNI extension. quik can peek at that and compare it to the
CONNECT target:

```toml
sni_enforce = true
```

If the SNI doesn't match (case-insensitive equality on the hostname), the
connection is aborted with a log line. Without `sni_enforce` the mismatch
is logged at WARN but the connection still proceeds.

This catches a class of bypass where a client opens
`CONNECT trusted.example.com:443` but then negotiates TLS for
`evil.attacker.com`. Whether you want to enforce depends on context:
enforcing breaks legitimate clients that legitimately reuse a CONNECT
tunnel for multiple TLS handshakes (rare but not unheard of).

## Authentication

Two modes, configured under `[egress.auth]`. Both are optional.

### `basic_log_only`

Extracts the Basic username from the CONNECT request, records it in the
access log, and proceeds. **No password validation.** Appropriate when the
network itself is the trust boundary and you only want to attribute each
request to a user.

```toml
[egress.auth]
mode  = "basic_log_only"
realm = "egress"
```

The realm is what users see in the browser / curl prompt.

### `jwt`

Reuses a `[[auth]]` block defined elsewhere in the config. The client puts
a Bearer token in `Proxy-Authorization`; quik validates it against the
named auth block's JWKS.

```toml
[[auth]]
name       = "main"
jwks_url   = "https://issuer.example.com/.well-known/jwks.json"
issuer     = "https://issuer.example.com/"
audience   = "egress"
algorithms = ["RS256"]

[egress.auth]
mode             = "jwt"
block            = "main"
originator_claim = "sub"     # what to log as the originator (default: sub)
```

JWT validation runs **before** the rule list - a missing or invalid token
returns `407 Proxy Authentication Required` regardless of destination.

Without an `[egress.auth]` block, no authentication is required; the access
log records `originator = "-"`.

## What the destination sees

The destination server sees the proxy's IP address, not the client's.
That's a property of CONNECT, not a quik decision - there's no header
quik can add inside the tunnel because the tunnel is opaque TLS.

If you need to attribute traffic at the destination, you need to do it at
the application layer inside the tunnel (e.g. an `Authorization` header in
the HTTPS request the client is making). Or run the destination behind a
quik reverse proxy too, and use JWT auth there.

## Observability

Egress emits its own metrics:

| Metric                          | Type    | Labels                                |
|---------------------------------|---------|---------------------------------------|
| `quik_egress_total`             | counter | `action` (`allow`/`deny`/`rejected_method`/`auth_failed`/...) |
| `quik_egress_bytes_client_total` | counter | client→destination bytes              |
| `quik_egress_bytes_server_total` | counter | destination→client bytes              |
| `quik_egress_active`            | gauge   | tunnels currently open                |

Every CONNECT attempt logs once at INFO, with `target`, `action`,
`originator`, `decision`, `sni`, `peer`. Denied requests log at WARN.

## Running egress alongside the reverse proxy

The two roles share the same binary, the same `[[auth]]` blocks, and the
same admin listener. A combined config looks like:

```toml
mode = "edge"

[listener]
bind = "0.0.0.0:8443"
[listener.tls]
cert_path = "/etc/quik/tls/cert.pem"
key_path  = "/etc/quik/tls/key.pem"

[admin]
bind = "127.0.0.1:9090"

[egress]
bind           = "0.0.0.0:3128"
default_action = "deny"

[[egress.rules]]
action = "allow"
hosts  = ["*.github.com"]

# ...the usual [[upstreams]] / [[routes]] for the reverse-proxy side...
```

If `[egress]` is absent, the egress listener simply isn't started - there's
no overhead for the reverse-proxy-only deployment.

## Things quik doesn't do

- **No HTTPS interception.** Tunnels are opaque TLS.
- **No HTTP/1.1 forward proxy (non-CONNECT).** Plain HTTP forwarding would
  expose request paths and headers to the proxy, which contradicts the
  rest of quik's posture (it's never on the path of plaintext credentials).
  Use CONNECT.
- **No request body inspection or rewriting.** If you need a true L7 egress
  firewall, this isn't the right tool.

## What to read next

- [Config reference](config-reference.md) - every `[egress.*]` field.
- [HA reverse proxy](ha-reverse-proxy.md) - the other half of the same
  binary.
