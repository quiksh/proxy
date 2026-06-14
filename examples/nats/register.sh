#!/bin/sh
# register.sh - a backend announces itself to quik via a NATS KV key and keeps
# the lease alive by re-putting it. Illustrative; a real service would do this
# in-process with async-nats - same shape: register, heartbeat, delete on stop.
#
# The heartbeat is GATED on a local liveness probe: the key is only refreshed
# while the instance answers. So if the service dies but this sidecar keeps
# running, the heartbeat stops, the lease (TTL) expires, and quik reaps it -
# the registry tracks liveness ("should this be registered?"), distinct from
# routing, which quik's own active health decides. (If the sidecar itself dies,
# the heartbeat also stops and the TTL expires it just the same. The remaining
# gap - a sidecar that outlives a dead instance - is closed by sharing fate with
# the instance; see docs/service-registration.md §6.)
set -eu

: "${NATS_URL:=nats://nats:4222}"
: "${BUCKET:=quik_registrations}"
: "${NAMESPACE:?set NAMESPACE}" "${SERVICE:?set SERVICE}"
: "${INSTANCE:?set INSTANCE}" "${ADDR:?set ADDR=host:port}"
: "${VERSION:=v1}" "${HEARTBEAT_SECS:=10}"   # TTL is 30s; refresh at ~T/3
# Liveness endpoint - "is this instance alive?", distinct from quik's routing
# probe. Set empty to disable the gate.
: "${LIVENESS_PATH:=/healthz?source=container}"

# Optional scoped JWT credential (recommended). Empty ⇒ no-auth (local demo).
CREDS_ARG=""
[ -n "${CREDS_FILE:-}" ] && CREDS_ARG="--creds ${CREDS_FILE}"

# Minimal JSON string-escaping for interpolated values (backslash + double-quote)
# so a value containing a quote can't produce malformed JSON.
esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

KEY="reg.${NAMESPACE}.${SERVICE}.${INSTANCE}"
VAL=$(printf '{"address":"%s","scheme":"http","weight":1,"metadata":{"version":"%s"}}' \
      "$(esc "$ADDR")" "$(esc "$VERSION")")

nats_cmd() { nats --server "$NATS_URL" $CREDS_ARG "$@"; }

# Alive iff the gate is disabled, or the instance answers its liveness endpoint.
# busybox wget exits non-zero on connection refused / timeout / HTTP >= 400.
alive() {
  [ -z "$LIVENESS_PATH" ] && return 0
  wget -q -T 2 -O /dev/null "http://${ADDR}${LIVENESS_PATH}" 2>/dev/null
}

# Graceful deregister on stop → quik drains the member (vs TTL expiry = hard drop).
trap 'nats_cmd kv del "$BUCKET" "$KEY" >/dev/null 2>&1 || true; exit 0' TERM INT

echo "registering $KEY -> $ADDR (heartbeat ${HEARTBEAT_SECS}s, liveness ${LIVENESS_PATH:-off})"
while :; do
  if alive; then
    nats_cmd kv put "$BUCKET" "$KEY" "$VAL" >/dev/null
  else
    echo "[$KEY] liveness probe failed - not refreshing; lease will expire"
  fi
  sleep "$HEARTBEAT_SECS"
done
