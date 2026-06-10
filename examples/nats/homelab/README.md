# End-to-end test — single-node NATS service registration

Spin up quik + NATS + two self-registering backends, send traffic, then
**deploy and provision a new service into the live pool** and watch quik pick it
up — no restart, no config change.

## Prerequisites

- Docker + Docker Compose, and `jq`.
- A NATS CLI is handy but optional. If you don't have it locally, run it from the
  bundled image:
  ```sh
  nats() { docker run --rm --network quik-nats natsio/nats-box nats -s nats:4222 "$@"; }
  ```
  (If you do have it: `nats -s localhost:4222 …`, since NATS is published on
  127.0.0.1:4222.)

All commands below are run from this directory (`examples/nats/homelab/`).

## 1. Bring it up

```sh
../../../scripts/gen-dev-cert.sh                 # once: self-signed cert into ../../../tls
docker compose up -d --build                     # builds quik (--features nats) + echo backend
```

First build takes a few minutes (it compiles quik). Subsequent ups are instant.

## 2. Verify it's healthy and the backends self-registered

```sh
curl -s localhost:9090/healthz                   # -> ok
curl -s localhost:9090/admin/pools/checkout | jq '.members[].address'
# -> "checkout-1.svc:8080"
#    "checkout-2.svc:8080"
```

Those two registered themselves on startup (each ships a registrar sidecar). If
the list is empty for a second, the active-health probe hasn't marked them
healthy yet — re-run.

## 3. Send traffic and see it load-balanced

The echo backend reports which instance served each request:

```sh
for i in $(seq 6); do curl -sk https://localhost:8443/ | jq -r .backend; done
# -> checkout-1 / checkout-2 / checkout-1 / ...   (least-connections spread)
```

## 4. Provision a NEW service into the live pool

This is the headline: deploy a brand-new backend and register it at runtime.

```sh
./provision.sh checkout-3
watch -n1 "curl -s localhost:9090/admin/pools/checkout | jq -c '.members[].address'"
```

Within ~1–2 s (a reconcile + one health probe) `checkout-3.svc:8080` joins the
pool, and traffic starts hitting it:

```sh
for i in $(seq 9); do curl -sk https://localhost:8443/ | jq -r .backend; done
# -> now includes checkout-3
```

You can also watch the registration land on the NATS side:

```sh
nats kv watch quik_registrations 'reg.shop.checkout.>'    # live put/delete feed
```

## 5. Operator-drain a member (operator-wins)

Cordon an instance without touching the service — the watcher applies the
override and drains it, even though it's still heartbeating:

```sh
nats kv put quik_registrations override.shop.checkout.checkout-3 '{"action":"drain"}'
# checkout-3 leaves the pool. Remove the override to bring it back:
nats kv del quik_registrations override.shop.checkout.checkout-3
```

## 6. Deprovision (graceful)

```sh
./deprovision.sh checkout-3
```

Stopping its registrar deletes the NATS key, so quik drains it (in-flight
finishes) before the container stops.

## 7. Failure drill — a backend dies (no graceful deregister)

```sh
docker kill checkout-2     # the service process; its registrar keeps running
```

Two independent mechanisms take it out of rotation:

- **Immediately:** quik's active-health probe to `checkout-2.svc:8080` starts
  failing, so quik marks it unhealthy and **stops routing to it** within a
  couple of probe intervals — even while it's still listed as a member.
  ```sh
  for i in $(seq 8); do curl -sk https://localhost:8443/ | jq -r .backend; done   # no checkout-2
  ```
- **Within one TTL (~30 s):** the registrar's heartbeat is health-gated, so once
  the service stops answering it stops refreshing the key; the lease expires and
  the watcher removes the member entirely.
  ```sh
  curl -s localhost:9090/admin/pools/checkout | jq '.members[].address'   # checkout-2 gone
  ```

These are the two halves of the liveness model: the **lease TTL** (refreshed by
the registrar) reaps anything that stops heartbeating — a dead service *or* a
dead sidecar — and quik's **active health** is the independent backstop that
stops traffic from quik's own vantage point, regardless of what the registry
says. (Kill the *sidecar* instead — `docker kill checkout-2-reg` — and the same
TTL expiry removes it, since nothing refreshes the key.)

## 8. Metrics

```sh
curl -s localhost:9090/metrics | grep -E 'quik_nats_|quik_pool_member_'
# quik_nats_connected, quik_nats_reconcile_total{action}, quik_nats_watch_events_total{op},
# quik_nats_registration_rejected_total{reason}, quik_pool_member_added/removed_total
```

Try an out-of-policy registration to see H1 reject it (loopback is outside the
`.svc` allow-list, so this is refused and counted):

```sh
nats kv put quik_registrations reg.shop.checkout.evil '{"address":"127.0.0.1:9","scheme":"http"}'
curl -s localhost:9090/metrics | grep 'reason="address_not_allowed"'
```

## 9. Tear down

```sh
./deprovision.sh checkout-3 2>/dev/null || true   # if still running
docker compose down -v                            # stops everything + removes the bucket volume
```
