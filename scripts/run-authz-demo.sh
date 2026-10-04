#!/usr/bin/env bash
# Run quik with a mock external authorizer and an echo backend, all on
# localhost, for validating [[authorizers]] behaviour end-to-end.
#
# What this does:
#   1. Generates the dev TLS cert into ./tls if missing.
#   2. Builds quik and the echo_backend / mock_authorizer examples.
#   3. Starts echo_backend (127.0.0.1:8080) and mock_authorizer
#      (127.0.0.1:9100) in the background.
#   4. Runs quik in the foreground with config/authorizer-demo.toml.
#   Ctrl-C stops all three.
#
# Env knobs:
#   CONFIG       quik config            (default: config/authorizer-demo.toml)
#   AUTHZ_RULES  mock authorizer rules  (default: config/mock-authorizer.toml)
#
# Then, from another shell:
#   ./scripts/authz-smoke.sh            # scripted checks of every outcome
#   curl -k https://localhost:8443/api/x -H 'x-api-key: dev-key'
#   curl -s localhost:9100/_mock/requests | jq   # what the authorizer saw

set -euo pipefail
cd "$(dirname "$0")/.."

CONFIG="${CONFIG:-config/authorizer-demo.toml}"
export AUTHZ_RULES="${AUTHZ_RULES:-config/mock-authorizer.toml}"

[[ -f tls/cert.pem && -f tls/key.pem ]] || ./scripts/gen-dev-cert.sh

cargo build --release --bin quik --example echo_backend --example mock_authorizer

pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

BIND_ADDR=127.0.0.1:8080 BACKEND_NAME=echo ./target/release/examples/echo_backend &
pids+=($!)
BIND_ADDR=127.0.0.1:9100 ./target/release/examples/mock_authorizer &
pids+=($!)

./target/release/quik --config "$CONFIG"
