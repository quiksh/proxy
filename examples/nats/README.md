# NATS service registration — examples

Backends register themselves into a NATS JetStream KV bucket; quik (built with
`--features nats`) watches the bucket and reconciles them into a pool. See
`docs/service-registration.md` for the design and security model.

Two runnable stacks:

| Example | Topology | Use |
|---------|----------|-----|
| [`homelab/`](homelab/) | 1 NATS node, 1 quik, 2 backends | single host / homelab |
| [`ha/`](ha/) | 3-node NATS cluster (R3 bucket), 2 quik | production-shaped |

Both build quik from this repo with [`Dockerfile.quik`](Dockerfile.quik)
(`cargo build --release --features nats`). Each backend runs a **`quik-register`**
sidecar (the agent in [`quik-register/`](../../quik-register)) configured by
[`quik-register.toml`](quik-register.toml): it health-checks the service and
registers it while healthy, deregisters it when it fails or on shutdown, and
heartbeats the lease in between. ([`register.sh`](register.sh) is a ~10-line
shell alternative for a no-build demo; a real service could also register
in-process with `async-nats`.)

## Quick start (homelab)

```sh
./scripts/gen-dev-cert.sh                                  # once: TLS cert into tls/
docker compose -f examples/nats/homelab/docker-compose.yml up -d --build
```

## The dev / operator loop

```sh
# what's registered (NATS' view)
nats kv ls   quik_registrations
nats kv watch quik_registrations 'reg.shop.checkout.>'      # live add/delete feed

# what quik resolved it into
curl -s localhost:9090/admin/pools/checkout | jq '.members[].address'

# operator-drain an instance — durable override, applied by the watcher
nats kv put quik_registrations override.shop.checkout.checkout-1 '{"action":"drain"}'
nats kv del quik_registrations override.shop.checkout.checkout-1     # undrain

# dead backend → stops heartbeating → TTL expires → drained (~30s)
docker compose -f examples/nats/homelab/docker-compose.yml stop checkout-1

# observability
curl -s localhost:9090/metrics | grep -E 'quik_nats_|quik_pool_member_'
```

## Addresses & the allow-list

The pool's `allow_addresses` gates which addresses a registration may claim — a
self-asserted address outside it is rejected (and counted on
`quik_nats_registration_rejected_total`). In these examples backends register as
`<name>.svc:8080` (a docker network alias), so a single `".svc"` host-suffix
admits the group; in a real homelab this is typically your LAN CIDR
(`["192.168.0.0/16"]`). Keep it as tight as the deployment allows — see the
"intra-allow-list" residual in the design doc.

## Auth

The bundled stacks run **no-auth NATS** so they come up in one command — fine on
a laptop / trusted LAN, never beyond it. For anything real use decentralised JWT
credentials:

```sh
./nats/bootstrap-creds.sh        # nsc: operator + SHOP account + scoped .creds
```

This mints a `checkout` cred that may publish *only*
`$KV.quik_registrations.reg.shop.checkout.>` and a `quik` cred that may subscribe
the bucket and publish `override.>`. Switch NATS to `nats/server-jwt.conf`, use
`tls://`, and mount the creds (the homelab/ha configs mark where). quik **warns**
if you point it at a non-`tls://` URL with credentials set.
