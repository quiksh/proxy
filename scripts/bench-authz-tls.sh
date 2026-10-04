#!/usr/bin/env bash
# Benchmark the cost of TLS / mTLS on the quik → pooled-authorizer hop.
#
# Runs the same closed-loop load through quik with an authorizer pool reached
# over plain HTTP, TLS, and mutual TLS - each twice:
#   keepalive : connections to the authorizer are pooled and reused (normal)
#   close     : the authorizer sends `Connection: close`, so every call opens a
#               new connection and does a full handshake (worst case)
# The authorizer cache is off and retries are 0, so every request makes
# exactly one authorizer call. Reports QPS, p50/p99, and CPU per 1k requests
# for quik and the authorizer.
#
# Env knobs:
#   CONCURRENCY  load_test concurrency     (default: 32)
#   DURATION     seconds per measurement   (default: 10)
#   MODES        which modes to run        (default: "http tls mtls")
#
# Everything binds to localhost, so absolute numbers reflect this machine
# (client, quik, backend, and authorizer share its cores). Compare the rows
# with each other, not with production.

set -euo pipefail
cd "$(dirname "$0")/.."

CONCURRENCY="${CONCURRENCY:-32}"
DURATION="${DURATION:-10}"
MODES="${MODES:-http tls mtls}"
WORK="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; wait 2>/dev/null; rm -rf "$WORK"' EXIT

cargo build -q --release --bin quik \
    --example echo_backend --example mock_authorizer --example load_test --example gen_test_pki
BIN=./target/release
EX=./target/release/examples

[[ -f tls/cert.pem && -f tls/key.pem ]] || ./scripts/gen-dev-cert.sh >/dev/null
"$EX/gen_test_pki" "$WORK/pki" 2>/dev/null

cat > "$WORK/rules.toml" <<'EOF'
[default]
inject = { "x-user-id" = "bench-user" }
EOF

BIND_ADDR=127.0.0.1:18080 BACKEND_NAME=echo "$EX/echo_backend" >/dev/null 2>&1 &

# Wait up to ~10s for a URL to answer; fail loudly rather than hang.
wait_for() {
    for _ in $(seq 1 50); do curl -sk -o /dev/null "$1" && return 0; sleep 0.2; done
    echo "timed out waiting for $1" >&2
    return 1
}
cpu_secs() { ps -o time= -p "$1" | python3 -c '
import sys
t = sys.stdin.read().strip()
parts = [float(p) for p in t.replace("-", ":").split(":")]
s = 0.0
for p in parts: s = s * 60 + p
print(s)'; }

run_mode() {
    local mode="$1" conn="$2"
    local scheme=http tls_line="" mock_env=()
    case "$mode" in
        tls)  scheme=https
              tls_line="tls = { ca_path = \"$WORK/pki/ca.pem\" }"
              mock_env=(TLS_CERT="$WORK/pki/server.pem" TLS_KEY="$WORK/pki/server.key") ;;
        mtls) scheme=https
              tls_line="tls = { ca_path = \"$WORK/pki/ca.pem\", cert_path = \"$WORK/pki/client.pem\", key_path = \"$WORK/pki/client.key\" }"
              mock_env=(TLS_CERT="$WORK/pki/server.pem" TLS_KEY="$WORK/pki/server.key"
                        TLS_CLIENT_CA="$WORK/pki/ca.pem") ;;
    esac
    [[ "$conn" == close ]] && mock_env+=(CONNECTION_CLOSE=1)

    # ${arr[@]+...}: an empty array is "unbound" under `set -u` in bash 3.2 (macOS).
    env BIND_ADDR=127.0.0.1:19100 AUTHZ_RULES="$WORK/rules.toml" ${mock_env[@]+"${mock_env[@]}"} \
        "$EX/mock_authorizer" >/dev/null 2>&1 &
    local mock_pid=$!

    cat > "$WORK/quik.toml" <<EOF
[listener]
bind = "127.0.0.1:18443"
[listener.tls]
cert_path = "./tls/cert.pem"
key_path  = "./tls/key.pem"
[admin]
bind = "127.0.0.1:19090"
[logging]
level = "error"

[[upstreams]]
name    = "echo"
members = [{ address = "127.0.0.1:18080" }]

[[upstreams]]
name    = "authz"
members = [{ address = "127.0.0.1:19100", scheme = "$scheme" }]
$tls_line

[[authorizers]]
name           = "bench"
upstream       = "authz"
path           = "/authorize"
retries        = 0
timeout_ms     = 2000
inject_headers = ["x-user-id"]

[[routes]]
path_prefix = "/"
authorizer  = "bench"
upstream    = "echo"
EOF
    "$BIN/quik" --config "$WORK/quik.toml" >/dev/null 2>&1 &
    local quik_pid=$!
    wait_for https://127.0.0.1:18443/

    # Warm-up (fills connection pools / JIT-free but primes caches).
    "$EX/load_test" https://127.0.0.1:18443/ -c "$CONCURRENCY" -d 2 >/dev/null 2>&1

    local q0 m0 q1 m1
    q0=$(cpu_secs "$quik_pid"); m0=$(cpu_secs "$mock_pid")
    "$EX/load_test" https://127.0.0.1:18443/ -c "$CONCURRENCY" -d "$DURATION" \
        > "$WORK/out.txt" 2>/dev/null
    q1=$(cpu_secs "$quik_pid"); m1=$(cpu_secs "$mock_pid")

    python3 - "$mode" "$conn" "$q0" "$q1" "$m0" "$m1" "$WORK/out.txt" <<'PY'
import re, sys
mode, conn, q0, q1, m0, m1, path = sys.argv[1:]
out = open(path).read()
num = lambda k: float(re.search(rf"{k}\s*:\s*([\d.]+)", out).group(1))
reqs, errs, qps = num("Requests"), num("Errors"), num("QPS")
p50, p99 = num("p50"), num("p99")
per_k = lambda a, b: (float(b) - float(a)) / max(reqs, 1) * 1000 * 1000  # ms per 1k req
print(f"| {mode:<5} | {conn:<9} | {qps:>8.0f} | {p50/1000:>7.2f} | {p99/1000:>7.2f} | "
      f"{per_k(q0, q1):>9.1f} | {per_k(m0, m1):>10.1f} | {int(errs):>6} |")
PY
    kill "$quik_pid" "$mock_pid" 2>/dev/null; wait "$quik_pid" "$mock_pid" 2>/dev/null || true
}

echo
echo "concurrency=$CONCURRENCY duration=${DURATION}s, $(uname -sm), cache off, retries 0"
echo
echo "| mode  | authz conn | QPS      | p50 ms  | p99 ms  | quik CPU* | authz CPU* | errors |"
echo "|-------|-----------|----------|---------|---------|-----------|------------|--------|"
for mode in $MODES; do
    for conn in keepalive close; do
        run_mode "$mode" "$conn"
    done
done
echo
echo "* CPU-milliseconds per 1,000 requests (lower is better)."
