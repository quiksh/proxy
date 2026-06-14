#!/bin/sh
# Mint decentralised-JWT credentials for the HA (production-shaped) quik NATS
# demo, demonstrating the PER-SERVICE key model: checkout and blog get distinct
# credentials, each able to write only its own service's registrations. (The
# homelab stack uses the broader project-key model - see
# ../homelab/auth/gen-demo-creds.sh.) Tightening further to one credential per
# replica is just a narrower subject grant (reg.shop.<service>.<instance>).
#
# Runs entirely inside nats-box (bundles nsc), so you need only Docker:
#   docker run --rm -v "$PWD:/work" -w /work natsio/nats-box sh bootstrap-creds.sh
#
# Environment is the account/cluster boundary, NOT a key token (docs §4): an
# account named <env>-<region> is the hard wall. Re-run with ENV/REGION set for
# each environment - alpha/beta/gamma/prod each get a separate account (one
# cluster) or a separate cluster entirely. Credential files are named
# <service>-<env>-<region>.creds to make the identity obvious.
set -eu

ENV="${ENV:-prod}"
REGION="${REGION:-use1}"
ACCOUNT="shop-${ENV}-${REGION}"          # the env+region isolation boundary
SERVICES="${SERVICES:-checkout blog}"     # per-service identities to mint
B='$KV.quik_registrations'
OUT="${OUT:-./creds}"; mkdir -p "$OUT"

export XDG_DATA_HOME=./.nsc/local XDG_CONFIG_HOME=./.nsc/config \
       XDG_CACHE_HOME=./.nsc/cache NKEYS_PATH=./.nsc/nkeys
rm -rf ./.nsc

# Root of trust + the env/region account (JetStream enabled for KV).
nsc add operator --generate-signing-key --sys --name QUIK >/dev/null
nsc add account "$ACCOUNT" >/dev/null
nsc edit account "$ACCOUNT" --js-mem-storage -1 --js-disk-storage -1 \
                            --js-streams -1 --js-consumer -1 >/dev/null

# One credential PER SERVICE: may write only its own reg.shop.<service>.* subtree
# (+ the JetStream stream-info and reply-inbox a KV open/put needs), never
# override.* and never another service's keys. This is what makes checkout
# unable to register or steer blog, and vice versa.
for svc in $SERVICES; do
  nsc add user -a "$ACCOUNT" -n "$svc" \
    --allow-pub "${B}.reg.shop.${svc}.>" \
    --allow-pub '$JS.API.STREAM.INFO.KV_quik_registrations' \
    --allow-sub '_INBOX.>' >/dev/null
  nsc generate creds -a "$ACCOUNT" -n "$svc" > "${OUT}/${svc}-${ENV}-${REGION}.creds"
done

# quik: subscribe the whole bucket (the watch) + write override.* (admin facade).
nsc add user -a "$ACCOUNT" -n quik \
  --allow-sub "${B}.>" --allow-pub "${B}.override.>" \
  --allow-pub '$JS.API.>' --allow-sub '_INBOX.>' >/dev/null
nsc generate creds -a "$ACCOUNT" -n quik > "${OUT}/quik-${ENV}-${REGION}.creds"

# admin: full account, for one-time bucket creation.
nsc add user -a "$ACCOUNT" -n admin --allow-pub '>' --allow-sub '>' >/dev/null
nsc generate creds -a "$ACCOUNT" -n admin > "${OUT}/admin-${ENV}-${REGION}.creds"

# Server config (operator + mem-resolver with the account inline). Add a
# cluster{} block per node, mount on every nats-N, and add JetStream + TLS.
nsc generate config --mem-resolver --config-file "${OUT}/resolver-${ENV}-${REGION}.conf" >/dev/null
rm -rf ./.nsc

echo
echo "Minted into ${OUT}/ for account ${ACCOUNT}:"
for svc in $SERVICES; do
  echo "  ${svc}-${ENV}-${REGION}.creds   pub ${B}.reg.shop.${svc}.> only"
done
cat <<EOF
  quik-${ENV}-${REGION}.creds       sub ${B}.> ; pub ${B}.override.>
  admin-${ENV}-${REGION}.creds      full account (bucket creation)
  resolver-${ENV}-${REGION}.conf    operator + accounts (add cluster{}, jetstream{}, tls{})

Wire it (mirrors ../homelab/docker-compose.yml, scaled to the cluster):
  - mount resolver-*.conf on each nats-N; add its cluster{} routes + jetstream{}
  - quik:         creds_file = quik-${ENV}-${REGION}.creds, url tls://
  - each backend: its own <service>-${ENV}-${REGION}.creds
A different env/region is a separate account:  ENV=beta REGION=euw1 sh $0
EOF
