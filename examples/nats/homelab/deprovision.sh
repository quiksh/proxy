#!/bin/sh
# Gracefully remove a backend provisioned with ./provision.sh. Stopping the
# registrar fires its SIGTERM trap, which deletes the NATS key → quik drains the
# member (in-flight finishes) before the service container stops.
#
#   ./deprovision.sh checkout-3
set -eu

INSTANCE="${1:?usage: deprovision.sh <instance>}"

docker stop "$INSTANCE-reg" >/dev/null 2>&1 || true   # registrar deletes its key → drain
sleep 1
docker stop "$INSTANCE" >/dev/null 2>&1 || true

echo "deprovisioned $INSTANCE  (drained from the pool, containers stopped)"
