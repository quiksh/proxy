# Admin API — online management

The admin listener serves three things:

- `/healthz` — liveness probe. 200 normally; 503 once drain begins.
- `/metrics` — Prometheus exposition.
- `/admin/pools/*` — manage upstream members on a running proxy.

This page is about the third one. The first two are described in
[HA reverse proxy](ha-reverse-proxy.md#observability).

## Why it exists

Restarting a proxy in front of live traffic is annoying — every TLS session
has to renegotiate, every long-lived connection drops, and any in-flight
request gets aborted unless you orchestrate a careful drain. The admin API
lets you do the things that historically motivated restarts (add a backend,
remove a dead one, roll a deploy) without touching the process.

Members added via the API live alongside the ones from the config file. On
restart, only the file is read — so persistent fleet state still belongs in
the config. The API is for live changes.

## Endpoints

| Method | Path                                                 | What it does                                    |
|--------|------------------------------------------------------|-------------------------------------------------|
| GET    | `/admin/pools`                                       | List every pool with its members.               |
| GET    | `/admin/pools/{pool}`                                | One pool's full state.                          |
| GET    | `/admin/pools/{pool}/members/{id}`                   | One member's full state.                        |
| POST   | `/admin/pools/{pool}/members`                        | Add a new member.                               |
| POST   | `/admin/pools/{pool}/members/{id}/drain`             | Stop routing to a member, wait for in-flight.   |
| POST   | `/admin/pools/{pool}/members/{id}/undrain`           | Cancel a drain; member becomes active again.    |
| DELETE | `/admin/pools/{pool}/members/{id}`                   | Drain, then remove from the pool.               |
| GET    | `/admin/config/snapshot`                             | Live upstream state as TOML — for promoting runtime changes back to the config file. |

Member `{id}` is the member's `address` (`host:port`), URL-encoded if
needed.

## Config drift

The config file is the source of truth — pools, routes, auth blocks, and
listeners only ever come from it. The admin API is for *tactical* live
changes within that structure (add/drain/remove members in an existing
pool). Anything you add via the API is lost on restart unless you also
update the config file.

To make the drift visible, every member in admin responses carries a
`source` field:

| Value       | Meaning                                                       |
|-------------|---------------------------------------------------------------|
| `"config"`  | Present in the config file at boot. Will survive a restart.   |
| `"runtime"` | Added via the admin API since boot. Will be lost on restart.  |

And `GET /admin/config/snapshot` renders the live upstream state as TOML:

```bash
curl -s http://127.0.0.1:9090/admin/config/snapshot
```

```toml
# Live upstream snapshot.
#
# Pools, routes, auth blocks, and listeners are static at runtime —
# consult your original config file for those sections. The blocks
# below reflect live state including any runtime-added members.
#
# Each member is annotated with its provenance:
#   `source: config`   was present in the config file at boot
#   `source: runtime`  added via the admin API since boot

[[upstreams]]
name = "api"
balancer = "round_robin"
members = [
    { address = "10.0.0.5:8080", scheme = "http" },  # source: config
    { address = "10.0.0.6:8080", scheme = "http" },  # source: config
    { address = "10.0.0.7:8080", scheme = "http" },  # source: runtime
]
```

The output is scoped to `[[upstreams]]` blocks — nothing else can drift at
runtime. Diff against your config file, paste the `runtime` members across
when you're ready to make them durable, and the next restart will pick
them up.

## State machine

Each member has two orthogonal state axes:

**Lifecycle** (operator-controlled):

```
  active  ──(POST .../drain or DELETE)──►  draining  ──(timeout or zero in-flight)──►  drained
     ▲                                          │
     └─────────────(POST .../undrain)───────────┘
```

A member is **routable** only when `lifecycle = active` and active health
isn't currently marking it unhealthy. `draining` members don't receive new
requests; in-flight ones finish (or are aborted on drain timeout).

`DELETE` and `POST .../drain` do the same thing initially — they put the
member in `draining`. The difference is what happens when drain completes:

- `DELETE` removes the member from the pool entirely. Gone.
- `POST .../drain` leaves it in `drained` — still in the pool, still
  inspectable, but not routable. Useful for "cordon" semantics.

`POST .../undrain` only works on `draining` or `drained` members. It puts
the lifecycle back to `active`.

**Active health** (probe-controlled, only when configured): `initial →
healthy ↔ unhealthy`. The admin API doesn't change this — only the probe
task does.

## Examples

Open admin listener (default — no auth):

```bash
ADMIN=http://127.0.0.1:9090

# List everything
curl -s "$ADMIN/admin/pools" | jq

# One pool
curl -s "$ADMIN/admin/pools/api" | jq

# One member
curl -s "$ADMIN/admin/pools/api/members/10.0.0.5:8080" | jq
```

Add a member:

```bash
curl -s -X POST "$ADMIN/admin/pools/api/members" \
     -H 'content-type: application/json' \
     -d '{"address": "10.0.0.7:8080", "scheme": "http"}'
```

Response: `201 Created` with the new member's detail object. `scheme`
defaults to `http`. `409 Conflict` if a member with that address already
exists.

Drain a member (stop routing, leave it in the pool):

```bash
curl -s -X POST "$ADMIN/admin/pools/api/members/10.0.0.5:8080/drain"
```

Response: `202 Accepted` with `lifecycle = "draining"`. The drain task
polls in-flight to zero, then transitions to `drained`. Drain timeout
defaults to `[upstreams.drain].timeout_ms` (60 s); after that the member
is forcibly drained regardless of remaining traffic.

Undrain (cancel):

```bash
curl -s -X POST "$ADMIN/admin/pools/api/members/10.0.0.5:8080/undrain"
```

Only succeeds on a `draining` or `drained` member — `409 Conflict` on an
already-active one. A member that's been `DELETE`d is gone and can't be
undrained.

Remove a member entirely:

```bash
curl -s -X DELETE "$ADMIN/admin/pools/api/members/10.0.0.5:8080"
```

## Rolling a deploy

The classic flow:

```bash
ADMIN=http://127.0.0.1:9090
POOL=api

# 1. Add the new backend.
curl -s -X POST "$ADMIN/admin/pools/$POOL/members" \
     -H 'content-type: application/json' \
     -d '{"address": "10.0.0.7:8080", "scheme": "http"}'

# 2. Drain the old one and wait for it to finish.
curl -s -X DELETE "$ADMIN/admin/pools/$POOL/members/10.0.0.5:8080"

# 3. Poll until it's gone.
while curl -sf "$ADMIN/admin/pools/$POOL/members/10.0.0.5:8080" >/dev/null; do
    sleep 1
done
echo "old backend drained"
```

If you're cycling multiple backends, drain them one at a time — don't drain
the whole pool simultaneously or every request hits "no upstream available".

## Authentication

The admin listener defaults to **no authentication**. That's fine on a
loopback bind (`127.0.0.1:9090`) inside a controlled host, and risky
anywhere else. Two modes are available.

### Bearer token

```toml
[admin.auth.write]
mode      = "bearer_token"
token_env = "QUIK_ADMIN_TOKEN"
```

`token_env` names an environment variable the proxy reads at startup. The
variable must be a non-empty string; a missing or empty variable fails
boot loudly. Clients send `Authorization: Bearer <token>` on every
mutating request.

`read` and `write` are separate auth groups. The default leaves `read`
open and asks you to set `write` — reads expose the same data as
`/metrics`, so the typical posture is to authenticate only mutations.

### mTLS

```toml
[admin.tls]
cert_path      = "./tls/admin-cert.pem"
key_path       = "./tls/admin-key.pem"
client_ca_path = "./tls/admin-client-ca.pem"

[admin.auth.write]
mode = "mtls"
```

When any auth group is `mtls`, the entire admin listener becomes TLS.
Clients have to present a certificate signed by `client_ca_path`. The
SHA-256 fingerprint of the verified cert is recorded in the audit log as
the principal.

You can mix: e.g. `read = none` (loopback fine for monitoring), `write =
mtls` (only operators with a key can mutate).

## Audit log

Every authenticated mutating request emits one structured log event at
`target = quik::admin::audit`. Fields:

| Field        | Value                                                         |
|--------------|---------------------------------------------------------------|
| `event`      | `member_added`, `member_drained`, `member_removed`, `member_undrained`, `admin_auth_fail` |
| `peer`       | Client socket address.                                        |
| `principal`  | Bearer-token-keyed name, mTLS cert fingerprint, or `-` for unauth. |
| `pool`       | Pool name.                                                    |
| `member`     | Member ID where applicable.                                   |
| `path`       | Request URI path.                                             |
| `duration_ms`| Wall-clock from request receipt to response.                  |
| `outcome`    | `ok`, `not_found`, `conflict`, `bad_request`.                 |

These are separate from access logs. Filter independently:

```bash
RUST_LOG="info,quik::admin::audit=info"
```

## Error responses

JSON body, `error` field carrying a human-readable message:

| Status | Cause                                                                  |
|--------|------------------------------------------------------------------------|
| 400    | Malformed request body, invalid address, invalid scheme.               |
| 401    | Missing or invalid `Authorization` (or no client cert under mTLS).     |
| 404    | Unknown pool or member.                                                |
| 409    | Conflict — member already exists on add, or undrain on active member.  |
| 503    | Pool has no eligible members (drain-all guard).                        |

Example:

```json
{"error": "pool not found"}
```

## What it doesn't do

- **No pool creation/deletion.** Pools come from the config file. The API
  manages members inside existing pools.
- **No route editing.** Same reason — routes are in config.
- **No persistence.** Restart loses any API-only changes. Putting changes
  in your config file is the source of truth.
- **No bulk operations.** Drain one member at a time so you can observe
  before continuing.

## What to read next

- [HA reverse proxy](ha-reverse-proxy.md) — the deployment patterns that
  make this API useful.
- [Config reference](config-reference.md) — `[admin]` and `[admin.auth.*]`
  fields.
