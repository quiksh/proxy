#!/bin/sh
# Provision a NEW backend into the live pool, end to end: start the service
# container and a registrar that heartbeats it into NATS. quik's watcher picks
# it up within a reconcile + one health probe.
#
#   ./provision.sh checkout-3
#
# Requires the homelab stack to be up (docker compose ... up -d) so the
# `quik-nats` network and the `quik-echo:demo` image exist.
set -eu

INSTANCE="${1:?usage: provision.sh <instance>   e.g. checkout-3}"
NET=quik-nats
IMAGE=quik-echo:demo
BUCKET=quik_registrations
HERE=$(cd "$(dirname "$0")" && pwd)

# 1. Deploy the service (alias <instance>.svc so it matches the ".svc" allow-list).
docker run -d --rm --name "$INSTANCE" \
  --network "$NET" --network-alias "$INSTANCE.svc" \
  -e BIND_ADDR=0.0.0.0:8080 -e BACKEND_NAME="$INSTANCE" \
  "$IMAGE" >/dev/null

# 2. Register + heartbeat it (the registrar deletes the key on stop → graceful).
docker run -d --rm --name "$INSTANCE-reg" --network "$NET" \
  -v "$HERE/../register.sh:/scripts/register.sh:ro" \
  -e NATS_URL=nats://nats:4222 \
  -e NAMESPACE=shop -e SERVICE=checkout -e INSTANCE="$INSTANCE" \
  -e ADDR="$INSTANCE.svc:8080" \
  natsio/nats-box /bin/sh /scripts/register.sh >/dev/null

echo "provisioned $INSTANCE  (reg.shop.checkout.$INSTANCE -> $INSTANCE.svc:8080)"
echo "watch it join:  curl -s localhost:9090/admin/pools/checkout | jq '.members[].address'"
