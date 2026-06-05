#!/bin/sh
# register.sh — a backend announces itself to quik via a NATS KV key and keeps
# the lease alive by re-putting it. Design preview; illustrative.
#
# A real service would do this in-process with async-nats; the loop is the same
# shape: put on start, re-put as heartbeat, delete on graceful shutdown.
set -eu

: "${NATS_URL:=nats://nats:4222}"
: "${BUCKET:=quik_registrations}"
: "${NAMESPACE:?set NAMESPACE}" "${SERVICE:?set SERVICE}"
: "${INSTANCE:?set INSTANCE}" "${ADDR:?set ADDR=host:port}"
: "${VERSION:=v1}" "${HEARTBEAT_SECS:=10}"   # TTL is 30s; refresh at ~T/3

# Optional scoped JWT credential (recommended). Empty ⇒ no-auth (local demo).
CREDS_ARG=""
[ -n "${CREDS_FILE:-}" ] && CREDS_ARG="--creds ${CREDS_FILE}"

KEY="reg.${NAMESPACE}.${SERVICE}.${INSTANCE}"
VAL=$(printf '{"address":"%s","scheme":"http","weight":1,"metadata":{"version":"%s"}}' \
      "$ADDR" "$VERSION")

nats_cmd() { nats --server "$NATS_URL" $CREDS_ARG "$@"; }

# Graceful deregister on stop → quik drains the member (vs TTL expiry = hard drop).
trap 'nats_cmd kv del "$BUCKET" "$KEY" >/dev/null 2>&1 || true; exit 0' TERM INT

echo "registering $KEY -> $ADDR (heartbeat ${HEARTBEAT_SECS}s)"
while :; do
  nats_cmd kv put "$BUCKET" "$KEY" "$VAL" >/dev/null
  sleep "$HEARTBEAT_SECS"
done
