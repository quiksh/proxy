#!/usr/bin/env bash
# Shared-fate supervisor for a tier-2b bundle: the service and the quik-register
# sidecar run in ONE container, and neither may outlive the other. This is what
# makes bundling a *correctness* upgrade over a separate registrar (tier 3) - the
# registrar cannot zombie, because if the service dies this script tears the
# registrar down too (docs/service-registration.md §6).
#
# Needs bash (for `wait -n` and arrays); a real service image usually has it.
# For a shell-only base, swap in a supervisor like dumb-init + s6 / supervisord.
set -euo pipefail

pids=()
term() { trap - TERM INT; kill -TERM "${pids[@]}" 2>/dev/null || true; }
trap term TERM INT

# The registrar first (it heartbeats while the service is up; on SIGTERM it
# deregisters so quik drains us gracefully rather than waiting for the TTL).
quik-register --config /etc/quik-register/quik-register.toml & pids+=("$!")

# Then the service itself. Swap `echo_backend` for your service's entrypoint.
echo_backend & pids+=("$!")

# Block until WHICHEVER exits first, then signal the other and reap both.
wait -n
term
wait
