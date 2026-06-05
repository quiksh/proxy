# HA NATS service registration

A production-shaped topology: a **3-node NATS JetStream cluster** holding a
3-replica registration bucket, and **two quik instances** that each watch it
independently. NATS fans out every `kv.put` to both quik instances, so they
converge on the same membership with no coordination between them.

```
                 ┌──────── NATS cluster (R3 bucket) ────────┐
 backends ──put──▶  nats-1  ⇄  nats-2  ⇄  nats-3            │
                 └───▲───────────────────────────▲──────────┘
                  watch                        watch
                     │                            │
                  quik-a                       quik-b      ← put an LB / DNS RR
                     └──────────── traffic ───────┘           in front of these
```

## Run

```sh
../../../scripts/gen-dev-cert.sh
docker compose -f examples/nats/ha/docker-compose.yml up -d --build

# both instances see the same members
curl -s localhost:9090/admin/pools/checkout | jq '.members[].address'   # quik-a
curl -s localhost:9091/admin/pools/checkout | jq '.members[].address'   # quik-b
```

## Failure drills

- **Lose a NATS node:** `docker compose ... stop nats-1`. The cluster keeps a
  quorum (2/3), the bucket stays available, both quik stay converged.
- **Lose a backend:** `docker compose ... stop checkout-1`. Its key TTL-expires
  (or its registrar deletes it on graceful stop) and it drains out of *both*
  quik within a reconcile.
- **Total NATS outage** (`stop nats-1 nats-2 nats-3`): both quik **freeze** on
  last-known membership and keep serving — they never flush. On recovery they
  re-snapshot and reconcile forward.

## What you'd add for production

- **A load balancer / DNS round-robin in front of quik-a/quik-b** (this compose
  exposes them on separate host ports for inspection; it does not front them).
  Roll quik instances with `pre_drain_grace_seconds` so the LB withdraws each
  before it drains.
- **TLS + JWT on NATS.** Switch `url` to `tls://`, generate scoped per-service
  credentials with `../nats/bootstrap-creds.sh`, point NATS at
  `../nats/server-jwt.conf`, and mount each service's `.creds`. A service may
  publish only its own `reg.<ns>.<service>.*`; **only operators may write
  `override.>`** (enforce this in the account — it's what makes operator drains
  un-resurrectable).
- **JetStream account limits** (max keys/bytes) so a noisy writer is bounded
  server-side, and **caps sized for blue/green overlap** (blue + green ≈ 2×).
- A real quorum lives across **failure domains** (3 AZs), not one host.
