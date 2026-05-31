#!/usr/bin/env bash
# Generate a self-signed TLS cert for local development / docker-compose.
#
# Output:
#   tls/cert.pem
#   tls/key.pem
#
# SANs cover: localhost, the 'quik' service name (docker-compose), and 127.0.0.1.

set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p tls

openssl req -x509 -newkey rsa:2048 -keyout tls/key.pem -out tls/cert.pem \
  -sha256 -days 365 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:quik,IP:127.0.0.1" \
  >/dev/null 2>&1

chmod 644 tls/cert.pem tls/key.pem

echo "Generated tls/cert.pem and tls/key.pem (CN=localhost, SAN: localhost,quik,127.0.0.1)"
