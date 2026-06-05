#!/bin/sh
# Mint decentralised-JWT credentials for the quik NATS demo. Illustrative —
# requires the `nsc` tool (https://github.com/nats-io/nsc). Exact flags vary by
# nsc version; the intent is what matters: each credential's permissions are
# embedded in the credential, scoped to exactly the subjects it may touch.
set -eu

BUCKET_SUBJECT='$KV.quik_registrations'
OUT="./creds"
mkdir -p "$OUT"

# Root of trust + isolation boundary.
nsc add operator QUIK_DEMO 2>/dev/null || true
nsc add account  SHOP      2>/dev/null || true

# ── A service: may publish ONLY its own registration subtree, reads nothing.
nsc add user --account SHOP --name checkout \
  --allow-pub "${BUCKET_SUBJECT}.reg.shop.checkout.>" \
  --deny-sub  '>'
nsc generate creds --account SHOP --name checkout > "${OUT}/checkout.creds"

# ── quik: reads the whole bucket; writes ONLY operator overrides.
nsc add user --account SHOP --name quik \
  --allow-sub "${BUCKET_SUBJECT}.>" \
  --allow-pub "${BUCKET_SUBJECT}.override.>"
nsc generate creds --account SHOP --name quik > "${OUT}/quik.creds"

# Export the operator JWT + resolver data the server reads (server-jwt.conf).
mkdir -p ./nats/jwt/resolver
nsc describe operator --raw > ./nats/jwt/operator.jwt
# `nsc push`/`nsc generate config` populate the resolver dir in a real setup.

cat <<EOF

Done. Wrote:
  ${OUT}/checkout.creds   (scope: pub ${BUCKET_SUBJECT}.reg.shop.checkout.>)
  ${OUT}/quik.creds       (scope: sub ${BUCKET_SUBJECT}.> ; pub ${BUCKET_SUBJECT}.override.>)

Next:
  - point the compose 'nats' volume at nats/server-jwt.conf
  - uncomment the creds mounts + creds_file/CREDS_FILE in docker-compose.yml,
    config/quik.toml, and the registrar env.
EOF
