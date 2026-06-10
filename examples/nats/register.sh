#!/bin/sh
# register.sh — a backend announces itself to quik via a NATS KV key and keeps
# the lease alive by re-putting it. Illustrative; a real service would do this
# in-process with async-nats — same shape: register, heartbeat, delete on stop.
#
# The heartbeat is GATED on a local health check: the key is only refreshed
# while the service answers. So if the service dies but this sidecar keeps
# running, the heartbeat stops, the lease (TTL) expires, and quik reaps it —
# the registry tracks liveness, not just "the sidecar is alive". (If the sidecar
# itself dies, the heartbeat also stops and the TTL expires it just the same.)
set -eu

: "${NATS_URL:=nats://nats:4222}"
: "${BUCKET:=quik_registrations}"
: "${NAMESPACE:?set NAMESPACE}" "${SERVICE:?set SERVICE}"
: "${INSTANCE:?set INSTANCE}" "${ADDR:?set ADDR=host:port}"
: "${VERSION:=v1}" "${HEARTBEAT_SECS:=10}"   # TTL is 30s; refresh at ~T/3
: "${HEALTH_PATH:=/healthz}"                  # set empty to disable the gate

# Optional scoped JWT credential (recommended). Empty ⇒ no-auth (local demo).
CREDS_ARG=""
[ -n "${CREDS_FILE:-}" ] && CREDS_ARG="--creds ${CREDS_FILE}"

KEY="reg.${NAMESPACE}.${SERVICE}.${INSTANCE}"
VAL=$(printf '{"address":"%s","scheme":"http","weight":1,"metadata":{"version":"%s"}}' \
      "$ADDR" "$VERSION")

nats_cmd() { nats --server "$NATS_URL" $CREDS_ARG "$@"; }

# Healthy iff the gate is disabled, or the service answers its health endpoint.
# busybox wget exits non-zero on connection refused / timeout / HTTP >= 400.
healthy() {
  [ -z "$HEALTH_PATH" ] && return 0
  wget -q -T 2 -O /dev/null "http://${ADDR}${HEALTH_PATH}" 2>/dev/null
}

# Graceful deregister on stop → quik drains the member (vs TTL expiry = hard drop).
trap 'nats_cmd kv del "$BUCKET" "$KEY" >/dev/null 2>&1 || true; exit 0' TERM INT

echo "registering $KEY -> $ADDR (heartbeat ${HEARTBEAT_SECS}s, health ${HEALTH_PATH:-off})"
while :; do
  if healthy; then
    nats_cmd kv put "$BUCKET" "$KEY" "$VAL" >/dev/null
  else
    echo "[$KEY] health check failed — not refreshing; lease will expire"
  fi
  sleep "$HEARTBEAT_SECS"
done
