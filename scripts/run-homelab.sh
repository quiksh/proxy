#!/usr/bin/env bash
# Run quik with the homelab config.
#
# What this does:
#   1. Generates a self-signed TLS cert with SANs for the homelab service
#      hostnames (proxmox.internal, plex.internal, truenas.internal) if
#      cert/key are missing.
#   2. Checks the proxy and admin ports aren't already in use.
#   3. Builds the release binary if needed.
#   4. Runs quik in the foreground.
#
# Env knobs:
#   CONFIG     path to TOML config            (default: config/homelab.toml)
#   TLS_DIR    where to store cert.pem/key.pem (default: ./tls)
#   SAN_HOSTS  comma-separated cert SANs       (default: proxmox.internal,plex.internal,truenas.internal,localhost)
#   CERT_DAYS  cert validity                   (default: 365)
#
# Usage:
#   ./scripts/run-homelab.sh
#   CONFIG=config/myconfig.toml ./scripts/run-homelab.sh
#
# Once it's running, test from another shell:
#   curl -k --resolve proxmox.internal:8443:127.0.0.1 \
#       https://proxmox.internal:8443/
#
# Or add the hostnames to /etc/hosts for browser use:
#   sudo sh -c 'echo "127.0.0.1 proxmox.internal plex.internal truenas.internal" >> /etc/hosts'

set -euox pipefail
cd "$(dirname "$0")/.."

CONFIG="${CONFIG:-config/homelab.toml}"
TLS_DIR="${TLS_DIR:-./tls}"
SAN_HOSTS="${SAN_HOSTS:-proxmox.internal,plex.internal,truenas.internal,localhost}"
CERT_DAYS="${CERT_DAYS:-365}"

# Discover the proxy + admin bind addresses from the config so the port
# check matches reality if the user has edited them.
extract_port() {
    awk -v section="[$1]" '
        $0 == section { in_section = 1; next }
        in_section && /^\[/ { in_section = 0 }
        in_section && /^[[:space:]]*bind[[:space:]]*=/ {
            n = split($0, parts, "\"")
            if (n >= 2) {
                addr = parts[2]
                if (match(addr, /:[0-9]+$/)) {
                    print substr(addr, RSTART+1)
                    exit
                }
            }
        }
    ' "$CONFIG"
}

# 1. Generate certs ──────────────────────────────────────────────────────────
if [[ ! -f "$TLS_DIR/cert.pem" || ! -f "$TLS_DIR/key.pem" ]]; then
    echo "==> Generating self-signed TLS cert at $TLS_DIR/"
    if ! command -v openssl >/dev/null 2>&1; then
        echo "ERROR: openssl not found on PATH"; exit 1
    fi
    mkdir -p "$TLS_DIR"
    san_dns_list=$(printf 'DNS:%s' "$(echo "$SAN_HOSTS" | sed 's/,/,DNS:/g')")
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$TLS_DIR/key.pem" -out "$TLS_DIR/cert.pem" \
        -sha256 -days "$CERT_DAYS" -nodes \
        -subj "/CN=quik-homelab" \
        -addext "subjectAltName=${san_dns_list},IP:127.0.0.1" \
        2>/dev/null
    chmod 644 "$TLS_DIR/cert.pem" "$TLS_DIR/key.pem"
    echo "    SANs: $SAN_HOSTS + 127.0.0.1"
    echo "    valid for: $CERT_DAYS days"
else
    echo "==> Using existing cert at $TLS_DIR/cert.pem"
    # Show the SANs that are in there in case the user has the wrong cert.
    if command -v openssl >/dev/null 2>&1; then
        openssl x509 -in "$TLS_DIR/cert.pem" -noout -text 2>/dev/null \
            | awk '/X509v3 Subject Alternative Name/{getline; gsub(/^[ \t]+/,""); print "    SANs:", $0}'
    fi
fi

# 2. Check the bind ports are free ──────────────────────────────────────────
proxy_port=$(extract_port listener || echo 8443)
admin_port=$(extract_port admin || echo 9090)
[[ -z "$proxy_port" ]] && proxy_port=8443
[[ -z "$admin_port" ]] && admin_port=9090

for port in "$proxy_port" "$admin_port"; do
    holder=""
    if command -v lsof >/dev/null 2>&1; then
        # lsof exits 1 when nothing is listening (which is what we want!).
        # Combined with `set -e -o pipefail` that would terminate the script,
        # so we explicitly tolerate the failure here. Note `|| true` inside
        # the substitution, not outside - outside doesn't help with pipefail.
        holder=$(lsof -iTCP:"$port" -sTCP:LISTEN -P -n 2>/dev/null \
            | awk 'NR==2{print $1"("$2")"}' \
            || true)
    fi
    if [[ -n "$holder" ]]; then
        echo "ERROR: port $port is already bound by $holder"
        echo "Hint: \`docker compose down\` if the demo stack is running,"
        echo "      or edit listener.bind / admin.bind in $CONFIG."
        exit 1
    fi
done

# 3. Build release ──────────────────────────────────────────────────────────
echo "==> Building (release)"
cargo build --release --quiet

# 4. Run ────────────────────────────────────────────────────────────────────
echo ""
echo "==> Starting quik (config: $CONFIG)"
echo "    proxy : https://localhost:${proxy_port}"
echo "    admin : http://localhost:${admin_port}"
echo ""
echo "    Test:"
echo "      curl -k --resolve proxmox.internal:${proxy_port}:127.0.0.1 \\"
echo "          https://proxmox.internal:${proxy_port}/"
echo "      curl -k --resolve plex.internal:${proxy_port}:127.0.0.1 \\"
echo "          http://plex.internal:${proxy_port}/  # plex is HTTP backend but TLS to the proxy"
echo "      curl http://localhost:${admin_port}/metrics  | grep ^quik_"
echo ""

exec ./target/release/quik --config "$CONFIG"
