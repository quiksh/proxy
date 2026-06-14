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
  last-known membership and keep serving - they never flush. On recovery they
  re-snapshot and reconcile forward.

## What you'd add for production

- **A load balancer / DNS round-robin in front of quik-a/quik-b** (this compose
  exposes them on separate host ports for inspection; it does not front them).
  Roll quik instances with `pre_drain_grace_seconds` so the LB withdraws each
  before it drains.
- **TLS + JWT on NATS - the per-service key model.** Switch `url` to `tls://`
  and mint **one credential per service** with
  [`../nats/bootstrap-creds.sh`](../nats/bootstrap-creds.sh): `checkout` and
  `blog` each get a `.creds` scoped to publish only their own
  `reg.shop.<service>.>` - `checkout` cannot register or steer `blog`, and
  neither can write `override.>` (only quik/operators can - that's what makes
  operator drains un-resurrectable). Mint per env/region into a **separate
  account** (`ENV=beta REGION=euw1 …`); env is the account/cluster boundary, not
  a key token (docs §4), and the creds are named `<service>-<env>-<region>`.
  This is the tighter step from the homelab **project key** (one cred for all
  services). Wiring mirrors `../homelab/docker-compose.yml` (mount the resolver
  config on each `nats-N`, give quik and each backend their creds), scaled to
  the cluster.
- **JetStream account limits** (max keys/bytes) so a noisy writer is bounded
  server-side, and **caps sized for blue/green overlap** (blue + green ≈ 2×).
- A real quorum lives across **failure domains** (3 AZs), not one host.
