#!/usr/bin/env bash
# Reproducible auth-path benchmark for the auth-demo stack.
#
# What it does, in one go:
#   1. Generates an Ed25519 keypair (overwriting any existing one).
#   2. Spawns mint_jwt.py serve in the background, hosting the JWKS.
#   3. Brings up docker compose (assumed to be mounting auth-demo.toml).
#   4. Mints user + service tokens that match the two [[auth]] blocks.
#   5. Warms each route with three requests.
#   6. Hammers each route with ab (keep-alive, configurable -n / -c).
#   7. Scrapes /metrics and reports a verdict on whether the JWKS cache is
#      doing its job - i.e. did we fetch the JWKS once, or N times?
#
# Cleanup: the JWKS server is killed on exit. docker compose is left running.
#
# Usage:
#   ./scripts/bench-auth.sh                   # 5000 requests, concurrency 32
#   ./scripts/bench-auth.sh 20000 64          # heavier
#   REQUESTS=2000 CONCURRENCY=8 ./scripts/bench-auth.sh
#
# Prereqs: docker, ab (apache2-utils), curl, python3 with PyJWT + cryptography.
# Assumes docker-compose.yml mounts config/auth-demo.toml - see README for the
# one-line sed to switch from docker.toml.

set -euo pipefail
cd "$(dirname "$0")/.."

REQUESTS="${1:-${REQUESTS:-5000}}"
CONCURRENCY="${2:-${CONCURRENCY:-32}}"
JWKS_PORT="${JWKS_PORT:-9999}"
PROXY_PORT="${PROXY_PORT:-8443}"
ADMIN_PORT="${ADMIN_PORT:-9090}"
JWKS_LOG="${TMPDIR:-/tmp}/quik-bench-jwks.log"

# ─── Prereq check ────────────────────────────────────────────────────────────
missing=0
for cmd in docker ab curl python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: '$cmd' is not on PATH"
        missing=1
    fi
done
if ! python3 -c 'import jwt, cryptography' 2>/dev/null; then
    echo "ERROR: python deps missing - install with: pip install PyJWT cryptography"
    missing=1
fi
(( missing == 0 )) || exit 1

# ─── Lifecycle ───────────────────────────────────────────────────────────────
JWKS_PID=""
cleanup() {
    if [[ -n "$JWKS_PID" ]] && kill -0 "$JWKS_PID" 2>/dev/null; then
        kill "$JWKS_PID" 2>/dev/null || true
        wait "$JWKS_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# ─── 1. Keys ─────────────────────────────────────────────────────────────────
echo "==> Generating fresh test keypair (overwrites scripts/test_keys/)"
python3 scripts/mint_jwt.py init --force >/dev/null

# ─── 2. JWKS server ──────────────────────────────────────────────────────────
echo "==> Starting JWKS server on port $JWKS_PORT (log: $JWKS_LOG)"
python3 scripts/mint_jwt.py serve --port "$JWKS_PORT" >"$JWKS_LOG" 2>&1 &
JWKS_PID=$!

for _ in $(seq 1 20); do
    if curl -fs "http://127.0.0.1:$JWKS_PORT/jwks.json" >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done
if ! curl -fs "http://127.0.0.1:$JWKS_PORT/jwks.json" >/dev/null 2>&1; then
    echo "ERROR: JWKS server didn't come up - see $JWKS_LOG"; exit 1
fi

# ─── 3. Stack ────────────────────────────────────────────────────────────────
echo "==> Bringing up docker compose (no-op if already running)"
docker compose up -d --build >/dev/null 2>&1 || {
    echo "ERROR: docker compose up failed"; exit 1
}

echo "==> Waiting for proxy admin /healthz"
for _ in $(seq 1 30); do
    if curl -fs "http://127.0.0.1:$ADMIN_PORT/healthz" 2>/dev/null | grep -q '^ok'; then
        break
    fi
    sleep 0.5
done
curl -fs "http://127.0.0.1:$ADMIN_PORT/healthz" 2>/dev/null | grep -q '^ok' || {
    echo "ERROR: proxy not responding on admin port $ADMIN_PORT"
    docker compose logs --tail=30 quik
    exit 1
}

# ─── 4. Tokens ───────────────────────────────────────────────────────────────
echo "==> Minting tokens"
USER_TOKEN=$(python3 scripts/mint_jwt.py sign \
    --sub user-42 \
    --claim 'roles=["admin","ops"]')
SERVICE_TOKEN=$(python3 scripts/mint_jwt.py sign \
    --aud internal \
    --claim 'service_id="billing-svc"' \
    --claim 'scope="read write"')

# ─── 5. Warm caches ──────────────────────────────────────────────────────────
echo "==> Warming caches"
for _ in 1 2 3; do
    curl -ks "https://127.0.0.1:$PROXY_PORT/open/warm" >/dev/null 2>&1 || true
    curl -ks -H "Authorization: Bearer $USER_TOKEN" \
        "https://127.0.0.1:$PROXY_PORT/api/warm" >/dev/null 2>&1 || true
    curl -ks -H "Authorization: Bearer $SERVICE_TOKEN" \
        "https://127.0.0.1:$PROXY_PORT/internal/warm" >/dev/null 2>&1 || true
done

scrape_metrics() {
    curl -fs "http://127.0.0.1:$ADMIN_PORT/metrics"
}

JWKS_BEFORE=$(scrape_metrics | grep '^quik_jwks_fetches_total{' || true)

# ─── 6. Bench ────────────────────────────────────────────────────────────────
echo ""
printf "==> ab: %d requests, concurrency %d, keep-alive\n" "$REQUESTS" "$CONCURRENCY"
echo ""
printf "%-26s %10s %14s %10s\n" "Route" "req/s" "ms/req (mean)" "failed"
printf "%-26s %10s %14s %10s\n" "-----" "-----" "-------------" "------"

run_ab() {
    local label="$1" url="$2" header="${3:-}"
    local args=(-k -q -c "$CONCURRENCY" -n "$REQUESTS")
    [[ -n "$header" ]] && args+=(-H "$header")
    ab "${args[@]}" "$url" 2>&1 | awk -v label="$label" '
        /Requests per second/      { rps = $4 }
        /Time per request:.*\(mean\)$/ && !mean { mean = $4 }
        /Failed requests/          { failed = $3 }
        END {
            if (rps == "") { rps = "?" }
            if (mean == "") { mean = "?" }
            if (failed == "") { failed = "?" }
            printf "%-26s %10.0f %14.2f %10s\n", label, rps, mean, failed
        }'
}

run_ab "anonymous /open/x"        "https://127.0.0.1:$PROXY_PORT/open/x"
run_ab "user-auth /api/x"         "https://127.0.0.1:$PROXY_PORT/api/x"      "Authorization: Bearer $USER_TOKEN"
run_ab "service-auth /internal/x" "https://127.0.0.1:$PROXY_PORT/internal/x" "Authorization: Bearer $SERVICE_TOKEN"

# ─── 7. JWKS verdict ─────────────────────────────────────────────────────────
JWKS_AFTER=$(scrape_metrics | grep '^quik_jwks_fetches_total{' || true)

echo ""
echo "==> JWKS fetch counters"
echo ""
fetches_value() {
    # Pull the trailing numeric value for a given line containing the label.
    # Returns 0 if no line is found.
    local snapshot="$1" auth="$2" outcome="$3"
    local v
    v=$(printf '%s\n' "$snapshot" \
        | awk -v auth="$auth" -v outcome="$outcome" '
            $0 ~ "auth=\""auth"\"" && $0 ~ "outcome=\""outcome"\"" { print $NF; exit }
        ')
    echo "${v:-0}"
}

total_delta=0
auth_requests_total=$(( REQUESTS * 2 ))   # /api/x + /internal/x

for block in users services; do
    before=$(fetches_value "$JWKS_BEFORE" "$block" "ok")
    after=$(fetches_value "$JWKS_AFTER"  "$block" "ok")
    # Integer math via shell - values are small integers.
    delta=$(( ${after%.*} - ${before%.*} ))
    total_delta=$(( total_delta + delta ))
    printf "  auth=%-10s  before: %4d   after: %4d   delta: %d\n" \
        "$block" "${before%.*}" "${after%.*}" "$delta"
done

echo ""
if (( total_delta <= 2 )); then
    printf "  \033[32mCACHE OK\033[0m: %d JWKS fetches across %d authenticated requests.\n" \
        "$total_delta" "$auth_requests_total"
else
    printf "  \033[33mCACHE THRASHING\033[0m: %d JWKS fetches across %d authenticated requests.\n" \
        "$total_delta" "$auth_requests_total"
    echo "  Most likely cause: the cached JWKS doesn't contain the token's kid."
    echo "  Either the token kid drifted (re-run \`init --force\` then bring the stack down/up),"
    echo "  or the JWKS endpoint isn't returning the kid we minted."
fi

echo ""
echo "Histogram (p50/p99 of JWKS fetch latency):"
scrape_metrics | grep -E '^quik_jwks_fetch_duration_seconds' | sed 's/^/  /'
echo ""
echo "Full /metrics: curl http://127.0.0.1:$ADMIN_PORT/metrics"
echo "JWKS server log: $JWKS_LOG"
