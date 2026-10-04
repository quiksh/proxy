#!/usr/bin/env bash
# Smoke-test a running authorizer demo (./scripts/run-authz-demo.sh) by
# driving every outcome through quik and checking the status - and, on allow,
# that the upstream saw the injected identity headers. Exits non-zero on the
# first mismatch, so it doubles as a CI-style integration check.
#
# Env knobs:
#   QUIK   proxy base URL        (default: https://localhost:8443)
#   AUTHZ  mock authorizer URL   (default: http://127.0.0.1:9100)

set -euo pipefail

QUIK="${QUIK:-https://localhost:8443}"
AUTHZ="${AUTHZ:-http://127.0.0.1:9100}"
pass=0

# check <name> <expected-status> <curl args...>
check() {
    local name="$1" want="$2"; shift 2
    local got
    got=$(curl -sk -o /tmp/authz-smoke.body -w '%{http_code}' "$@")
    if [[ "$got" != "$want" ]]; then
        echo "FAIL $name: want $want, got $got"
        cat /tmp/authz-smoke.body; echo
        exit 1
    fi
    echo "ok   $name ($got)"
    pass=$((pass + 1))
}

# body_has <name> <regex>: the last response body matches (grep -E).
body_has() {
    if ! grep -Eq -- "$2" /tmp/authz-smoke.body; then
        echo "FAIL $1: response body lacks '$2'"
        cat /tmp/authz-smoke.body; echo
        exit 1
    fi
    echo "ok   $1"
    pass=$((pass + 1))
}

curl -sf -X DELETE "$AUTHZ/_mock/requests" >/dev/null

check "public route needs no authorizer" 200 "$QUIK/public/x"
check "no credentials → 401"             401 "$QUIK/api/orders"
check "dev api key → 200"                200 "$QUIK/api/orders" -H 'x-api-key: dev-key'
body_has "upstream sees x-user-id"       '"x-user-id": ?"dev-user"'
check "bearer allow-alice → 200"         200 "$QUIK/api/orders" -H 'authorization: Bearer allow-alice'
body_has "user from bearer template"     '"x-user-id": ?"alice"'
check "admin without key → 403"          403 "$QUIK/api/admin/users" -H 'x-api-key: dev-key'
check "admin key → 200"                  200 "$QUIK/api/admin/users" -H 'x-api-key: admin-key'
check "spoofed x-user-id → 403"          403 "$QUIK/api/orders" -H 'x-api-key: dev-key' -H 'x-user-id: root'
check "authorizer 503 → fail closed"     503 "$QUIK/api/orders" -H 'x-mock-status: 503'
check "authorizer 429 relayed"           429 "$QUIK/api/orders" -H 'x-mock-status: 429'
check "authorizer timeout → 503"         503 "$QUIK/api/slow" -H 'x-mock-delay-ms: 1000'
check "small payment allowed"            200 "$QUIK/api/payments" -H 'x-api-key: dev-key' \
      -H 'content-type: application/json' -d '{"amount":50}'
body_has "body forwarded unchanged"      'amount\\":50'
check "large payment denied by body"     403 "$QUIK/api/payments" -H 'x-api-key: dev-key' \
      -H 'content-type: application/json' -d '{"amount":1000}'
check "body over cap → 413"              413 "$QUIK/api/payments" -H 'x-api-key: dev-key' \
      --data-binary @<(head -c 20000 /dev/zero | tr '\0' 'a')

recorded=$(curl -sf "$AUTHZ/_mock/requests")
if ! grep -q '"path":"/api/orders"' <<<"$recorded"; then
    echo "FAIL authorizer recorded no envelopes"; exit 1
fi
echo "ok   authorizer recorded envelopes"
pass=$((pass + 1))

echo "all $pass checks passed"
