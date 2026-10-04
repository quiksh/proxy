#!/usr/bin/env bash
# Throughput scaling sweep: quik worker threads × response size × mode.
#
#   rps : wrk over warm keep-alive connections (requests per second)
#   cps : `Connection: close` on every request, so each one is a fresh TCP +
#         TLS handshake (connections per second)
#
# For each size a `direct` row hits the static backend without quik (plain
# HTTP, keep-alive) - the ceiling this machine reaches with no proxy at all.
# quik always terminates TLS on the client side and proxies to the backend
# over plain HTTP; access logging is off.
#
# Output: CSV on stdout (and a progress line per run on stderr):
#   label,workers,size,mode,rps,p50_ms,p99_ms,mb_s,cpu_us_per_req,socket_errors
#
# Env knobs:
#   WORKERS          quik worker threads to sweep  (default: "1 2 4")
#   SIZES            response body bytes           (default: "0 1024 16384 131072")
#   MODES            rps and/or cps                (default: "rps cps")
#   DURATION         seconds per run               (default: 5)
#   CONNS            wrk connections for rps       (default: 256)
#   CPS_CONNS        wrk connections for cps       (default: 64)
#   WRK_THREADS      wrk threads                   (default: 3)
#   BACKEND_WORKERS  static backend worker threads (default: 3)
#   LABEL            tag written in each CSV row   (default: git short sha)
#   QUIK_BIN         quik binary to benchmark      (default: target/release/quik)
#   CPS_DURATION     seconds per cps run           (default: 3)
#   CPS_COOLDOWN     pause after a cps run so TIME_WAIT sockets free their
#                    ports (2 × MSL; macOS MSL is 15 s) (default: 32)
#
# Run it on Linux with the load generator on a separate machine (and quik
# pinned via `taskset`) for numbers that reflect quik rather than the box.

set -euo pipefail
cd "$(dirname "$0")/.."

WORKERS="${WORKERS:-1 2 4}"
SIZES="${SIZES:-0 1024 16384 131072}"
MODES="${MODES:-rps cps}"
DURATION="${DURATION:-5}"
CONNS="${CONNS:-256}"
CPS_CONNS="${CPS_CONNS:-64}"
WRK_THREADS="${WRK_THREADS:-3}"
BACKEND_WORKERS="${BACKEND_WORKERS:-3}"
LABEL="${LABEL:-$(git rev-parse --short HEAD)}"
QUIK_BIN="${QUIK_BIN:-./target/release/quik}"
CPS_DURATION="${CPS_DURATION:-3}"
CPS_COOLDOWN="${CPS_COOLDOWN:-32}"

command -v wrk >/dev/null || { echo "wrk is required (brew install wrk / apt install wrk)" >&2; exit 1; }
WORK="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; wait 2>/dev/null; rm -rf "$WORK"' EXIT

cargo build -q --release --bin quik --example static_backend
[[ -f tls/cert.pem && -f tls/key.pem ]] || ./scripts/gen-dev-cert.sh >/dev/null

cat > "$WORK/quik.toml" <<'EOF'
[listener]
bind = "127.0.0.1:18443"
[listener.tls]
cert_path = "./tls/cert.pem"
key_path  = "./tls/key.pem"
[admin]
bind = "127.0.0.1:19090"
[logging]
level = "warn"

[[upstreams]]
name    = "static"
members = [{ address = "127.0.0.1:18080" }]
[upstreams.pool]
max_idle_per_host = 1024

[[routes]]
path_prefix = "/"
upstream    = "static"
EOF

wait_for() {
    for _ in $(seq 1 50); do curl -sk -o /dev/null "$1" && return 0; sleep 0.1; done
    echo "timed out waiting for $1" >&2; return 1
}
cpu_secs() { ps -o time= -p "$1" | awk -F: '{ s = 0; for (i = 1; i <= NF; i++) s = s * 60 + $i; print s }'; }

# run <label> <workers> <size> <mode> <url> <pid-to-measure|0>
run() {
    local label="$1" workers="$2" size="$3" mode="$4" url="$5" pid="$6"
    local conns="$CONNS" dur="$DURATION" extra=()
    if [[ "$mode" == cps ]]; then
        conns="$CPS_CONNS"; dur="$CPS_DURATION"; extra=(-H "Connection: close")
    fi
    local c0=0 c1=0
    [[ "$pid" != 0 ]] && c0=$(cpu_secs "$pid")
    wrk -t"$WRK_THREADS" -c"$conns" -d"${dur}s" --latency ${extra[@]+"${extra[@]}"} "$url" \
        > "$WORK/wrk.txt" 2>&1 || true
    [[ "$pid" != 0 ]] && c1=$(cpu_secs "$pid")
    python3 - "$label" "$workers" "$size" "$mode" "$c0" "$c1" "$WORK/wrk.txt" <<'PY'
import re, sys
label, workers, size, mode, c0, c1, path = sys.argv[1:]
out = open(path).read()
def ms(pattern):
    m = re.search(pattern + r"\s+([\d.]+)(us|ms|s|m)\b", out)
    if not m:
        return float("nan")
    v, u = float(m.group(1)), m.group(2)
    return {"us": v / 1000, "ms": v, "s": v * 1000, "m": v * 60000}[u]
m = re.search(r"Requests/sec:\s+([\d.]+)", out)
if not m:
    # wrk failed outright (e.g. ephemeral ports exhausted) - record and move on.
    print(f"{label},{workers},{size},{mode},0,,,,,-1")
    print(f"  {label} workers={workers} size={size} {mode}: wrk failed:\n{out}", file=sys.stderr)
    sys.exit(0)
rps = float(m.group(1))
p50 = ms(r"50%")
p99 = ms(r"99%")
t = re.search(r"Transfer/sec:\s+([\d.]+)(\w+)", out)
mb = float(t.group(1)) * {"B": 1e-6, "KB": 1e-3, "MB": 1, "GB": 1e3}[t.group(2)]
dur = float(re.search(r"requests in ([\d.]+)(\w+),", out).group(1))
reqs = int(re.search(r"(\d+) requests in", out).group(1))
cpu = (float(c1) - float(c0)) / reqs * 1e6 if float(c1) > 0 and reqs else ""
errs = sum(int(x) for x in re.findall(r"(?:connect|read|write|timeout) (\d+)", out))
row = [label, workers, size, mode, f"{rps:.0f}", f"{p50:.2f}", f"{p99:.2f}", f"{mb:.1f}",
       f"{cpu:.1f}" if cpu != "" else "", str(errs)]
print(",".join(row))
print(f"  {label} workers={workers} size={size} {mode}: {rps:.0f}/s p99={p99:.2f}ms"
      f"{' cpu=%.1fus/req' % cpu if cpu != '' else ''}{' errors=%d' % errs if errs else ''}",
      file=sys.stderr)
PY
}

echo "label,workers,size,mode,rps,p50_ms,p99_ms,mb_s,cpu_us_per_req,socket_errors"
for size in $SIZES; do
    TOKIO_WORKER_THREADS="$BACKEND_WORKERS" BIND_ADDR=127.0.0.1:18080 BODY_BYTES="$size" \
        ./target/release/examples/static_backend >/dev/null 2>&1 &
    backend=$!
    wait_for http://127.0.0.1:18080/
    run "$LABEL" direct "$size" rps http://127.0.0.1:18080/ 0

    for workers in $WORKERS; do
        TOKIO_WORKER_THREADS="$workers" "$QUIK_BIN" --config "$WORK/quik.toml" >/dev/null 2>&1 &
        quik=$!
        wait_for https://127.0.0.1:18443/
        for mode in $MODES; do
            run "$LABEL" "$workers" "$size" "$mode" https://127.0.0.1:18443/ "$quik"
            # Let TIME_WAIT sockets from a cps run free their ports.
            if [[ "$mode" == cps ]]; then sleep "$CPS_COOLDOWN"; fi
        done
        kill "$quik"; wait "$quik" 2>/dev/null || true
    done
    kill "$backend"; wait "$backend" 2>/dev/null || true
done
